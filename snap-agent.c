#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/init.h>
#include <linux/sched.h>
#include <linux/kernel.h> 
#include <linux/slab.h>
#include <linux/fs.h>
#include <linux/errno.h>
#include <linux/timer.h>
#include <linux/types.h>
#include <linux/fcntl.h>
#include <linux/hdreg.h>
#include <linux/kdev_t.h>
#include <linux/vmalloc.h>
#include <linux/genhd.h>
#include <linux/blkdev.h>
#include <linux/bio.h>
#include <linux/sched.h>
#include <linux/blktrace_api.h>
#include <trace/events/block.h>
#include <linux/kthread.h>

//this is defined in 3.16 and up
#ifndef MIN_NICE
#define MIN_NICE -20
#endif

#define TARGET_NAME "/dev/sda"
#define SNAP_DEVICE_NAME "snap"
#define COW_FILE_NAME "/root/cowfile.snap"

struct copy_map{
	char* bitmap;
	int len;
};

struct snap_device{
	unsigned int sd_minor; //minor number of device
	unsigned int sd_refs; //number of users who have this snap device open
	sector_t sd_size; //size of device in sectors
	struct request_queue *sd_queue; //snap device request queue
	struct gendisk *sd_gd; //snap device gendisk
	struct block_device *sd_base_dev; //device being snapshot
	struct file *sd_cow_file; //cow file
	unsigned long sd_cow_inode; //cow file inode
	char *sd_bitmap; //bitmap of cow sectors
	struct task_struct *sd_kthread; //thread for handling file read/writes
	struct bio_list sd_pending_bios; //list of all bios yet to be processed
	spinlock_t sd_bio_lock; //lock for protecting actions on sd_pending_bios
	struct mutex sd_ctl_mutex; //mutex for all block_device_operations functions
	wait_queue_head_t sd_bio_event; //wait queue for triggering read/write thread
	
	int writes_performed; //for debug
	int writes_intercepted; //for debug
	unsigned long last_write_len; //for debug
	unsigned long last_inode_nr; //for debug
};

static int major;
static struct snap_device *snap;
static struct timer_list timer; //for debug

/********************************HELPER FUNCTIONS******************************/

static inline void mark_bitmap(char* bitmap, unsigned long long pos){
	bitmap[pos / 8] |= (1 << (pos % 8));
}

static inline int is_marked(char* bitmap, unsigned long long pos){
	return bitmap[pos / 8] & (1 << (pos % 8));
}

static struct copy_map *alloc_copy_map(unsigned short page_cnt){
	struct copy_map *cmap;
	unsigned short byte_cnt;
	
	//allocate copy_map struct
	cmap = kmalloc(sizeof(struct copy_map), GFP_NOIO);
	if(!cmap){
		printk(KERN_ERR "snap: could not allocate copy map\n");
		return NULL;
	}
	
	//calculate bitmap length
	byte_cnt = page_cnt/8;
	if(page_cnt % 8 != 0) byte_cnt++;
	cmap->len = byte_cnt;
	
	//allocate bitmap
	cmap->bitmap = kzalloc(byte_cnt, GFP_NOIO);
	if(!cmap->bitmap){
		printk(KERN_ERR "snap: could not allocate copy map bitmap\n");
		kfree(cmap);
		return NULL;
	}
	return cmap;
}

static inline void free_copy_map(struct copy_map *cmap){
	kfree(cmap->bitmap);
	kfree(cmap);
}

/*****************************BIO PROCESSING LOGIC*****************************/

static void write_sector(struct snap_device *dev, sector_t sect, char *data){
	ssize_t ret;
	mm_segment_t old_fs;
	loff_t offset = (loff_t)sect;
	
	//mark the sector as copied
	mark_bitmap(snap->sd_bitmap, sect);
	
	//change context for file write
	old_fs = get_fs();
	set_fs(get_ds());
	
	//perform the write
	ret = vfs_write(dev->sd_cow_file, data, 512, &offset);
	if(ret < 512){
		printk(KERN_ERR "snap: write failed to sector %llu\n", sect);
	}
	
	//revert context
	set_fs(old_fs);	
}

static void read_sector(struct snap_device *dev, sector_t sect, char *data){
	ssize_t ret;
	mm_segment_t old_fs;
	loff_t offset = (loff_t)sect;
	
	//change context for file write
	old_fs = get_fs();
	set_fs(get_ds());
	
	//perform the write
	ret = vfs_read(dev->sd_cow_file, data, 512, &offset);
	if(ret < 512){
		printk(KERN_ERR "snap: write failed to sector %llu\n", sect);
	}
	
	//revert context
	set_fs(old_fs);	
}

static void handle_bio(struct snap_device *dev, struct bio *bio){
	int i;
	struct bio_vec *bvec;
	struct copy_map *cmap;
	sector_t cur_sect;
	sector_t max_page_sect = bio->bi_sector;
	char *data;
	void *orig_private;
	bio_end_io_t *orig_end_io;

	if(bio_data_dir(bio)){
		cmap = bio->bi_private;
		
		dev->writes_performed += bio->bi_idx; //for debug
		
		//for each bio_vec in bio
		bio->bi_idx = 0; //TODO THIS IS PROBABLY GUNNA BREAK SHIT
		bio_for_each_segment(bvec, bio, i){
			cur_sect = max_page_sect;
			max_page_sect += bvec->bv_len/512;
			data = page_address(bvec->bv_page);
		
			//dont do anything if the write is to our file, just advance the sector
			if(!is_marked(cmap->bitmap, (unsigned long long)i)) continue;
			
			//for each sector in bvec_bv_page
			for(; cur_sect < max_page_sect; cur_sect++){
				//if we are not already tracking this sector
				if(!is_marked(dev->sd_bitmap, cur_sect)) write_sector(dev, cur_sect, data);
				data += 512;
			}
		}
		
		//free the bio
		free_copy_map(cmap);
		bio_put(bio);
	}else{	
		//save original data
		
		orig_private = bio->bi_private;
		orig_end_io = bio->bi_end_io;
		
		//submit the bio to the base device and wait for completion
		bio->bi_bdev = dev->sd_base_dev;
		bio_get(bio);
		submit_bio_wait(READ | REQ_SYNC, bio);
		
		//revert bio's original data
		bio->bi_private = orig_private;
		bio->bi_end_io = orig_end_io;
		
		//for each bio_vec
		bio_for_each_segment(bvec, bio, i){
			cur_sect = max_page_sect;
			max_page_sect += bvec->bv_len/512;
			data = page_address(bvec->bv_page);
			
			//for each sector in bvec_bv_page
			for(; cur_sect < max_page_sect; cur_sect++){
				//if we are tracking this sector, read it into the page
				if(is_marked(dev->sd_bitmap, cur_sect)) read_sector(dev, cur_sect, data);
				data += 512;
			}
		}
		
		/*
		bio->bi_bdev = dev->sd_base_dev;
		submit_bio_wait(READ | REQ_SYNC, bio);
		*/
		
		bio_endio(bio, 0);
		bio_put(bio);
	}
}

static int snap_bio_thread(void *data){
	struct snap_device *dev = data;
	struct bio *bio;

	//give this thread the highest priority we are allowed
	set_user_nice(current, MIN_NICE);
	
	while (!kthread_should_stop() || !bio_list_empty(&dev->sd_pending_bios)) {
		//wait for a bio to process or a kthread_stop call
		wait_event_interruptible(dev->sd_bio_event, kthread_should_stop() || !bio_list_empty(&dev->sd_pending_bios));
		if (bio_list_empty(&dev->sd_pending_bios)) continue;
		
		//safely dequeue a bio
		spin_lock_irq(&dev->sd_bio_lock);
		bio = bio_list_pop(&dev->sd_pending_bios);
		spin_unlock_irq(&dev->sd_bio_lock);
		
		//pass bio to handler
		handle_bio(dev, bio);
	}
	
	return 0;
}

/*********************************TRACING LOGIC********************************/

static inline unsigned long bvec_get_inode(struct bio_vec *bvec){
	if(!bvec->bv_page->mapping) return 0;
	if(!bvec->bv_page->mapping->host) return 0;
	return bvec->bv_page->mapping->host->i_ino;
}

//note do not printk in this function or the kernel will freeze
static void on_request(void *ignore, struct request_queue *q, struct bio *bio){
	int i, pages_marked = 0;
	struct bio_vec *bvec;
	struct bio *readbio;
	struct page *pg;
	struct copy_map *cmap = NULL;
	
	//if the intercepted bio is a write
	if(bio_data_dir(bio)){
		snap->writes_intercepted++; //for debug
	
		//allocate the read bio
		readbio = bio_alloc(GFP_NOIO, bio->bi_vcnt);
		if(!readbio){
			printk(KERN_ERR "snap: read bio allocation failed\n");
			goto trace_exit;
		}
		
		//populate read bio
		readbio->bi_bdev = bio->bi_bdev;
		readbio->bi_sector = bio->bi_sector;
		
		//allocate copy_map
		cmap = alloc_copy_map(bio->bi_vcnt);
		if(!cmap){
			printk(KERN_ERR "snap: copy_map allocation failed\n");
			goto trace_exit;
		}
		
		//allocate and add pages to mimic the original bio, also check inode
		bio_for_each_segment(bvec, bio, i){
			snap->last_write_len = bvec->bv_len; //for debug
			
			//allocate a page and add it to our bio
			pg = alloc_page(GFP_NOIO);
			if(!pg){
				printk(KERN_ERR "snap: read bio page %d allocation failed\n", i);
				goto trace_exit;
			}
			bio_add_page(readbio, pg, bvec->bv_len, bvec->bv_offset);
			
			//check the inode and mark the copy map if it does not match our cow file
			if(bvec_get_inode(bvec) != snap->sd_cow_inode){
				mark_bitmap(cmap->bitmap, (unsigned long long)i);
				pages_marked++;
			}
		}
		
		//if all sectors belong to the cow file, we don't need to trace this bio
		if(!pages_marked) goto trace_exit;
		
		//submit the bio and wait for the read to complete
		bio_get(readbio);
		submit_bio_wait(READ | REQ_SYNC, readbio);
		
		//check that read was successful
		if(!test_bit(BIO_UPTODATE, &readbio->bi_flags)){
			printk(KERN_ERR "snap: read of original sector failed\n");
			goto trace_exit;
		}
		
		//assign copy map to the bio, flag as write
		readbio->bi_private = cmap;
		readbio->bi_rw |= WRITE;
		
		//queue bio for processing by kernel thread
		spin_lock_irq(&snap->sd_bio_lock);
		bio_list_add(&snap->sd_pending_bios, readbio);
		spin_unlock_irq(&snap->sd_bio_lock);
		wake_up(&snap->sd_bio_event);
	}
	return;
	
trace_exit:
	//cleanup our read bio and copy map, no matter what state it was in
	if(cmap) free_copy_map(cmap);
	if(readbio){
		for(i=0; i<readbio->bi_vcnt; i++){
			if(&readbio->bi_io_vec[i]) __free_page((&readbio->bi_io_vec[i])->bv_page);
		}
		bio_put(readbio);
	}
}

/***************************BLOCK DEVICE DRIVER***************************/

//request handler
static void snap_make_request(struct request_queue *q, struct bio *bio){
	//queue bio for processing by kernel thread
	
	bio_get(bio);
	spin_lock_irq(&snap->sd_bio_lock);
	bio_list_add(&snap->sd_pending_bios, bio);
	spin_unlock_irq(&snap->sd_bio_lock);
	wake_up(&snap->sd_bio_event);
	
	
	//TODO make above work
	/*
	struct request_queue *target_q;
	bio->bi_bdev = snap->sd_base_dev;
	target_q = bdev_get_queue(bio->bi_bdev);
	target_q->make_request_fn(target_q, bio);
	*/
}

static struct block_device_operations snap_ops = {
	.owner = THIS_MODULE,
};

/************************DEVICE SETUP AND DESTROY************************/

//setup helper functions
static int setup_backing_device(struct snap_device *dev, const char *target_name){
	struct request_queue *q;

	//get reference target block device
	printk(KERN_ERR "snap: find block device '%s'\n", target_name);
	dev->sd_base_dev = blkdev_get_by_path(target_name, FMODE_READ, dev);
	if(IS_ERR(dev->sd_base_dev)){
		printk(KERN_ERR "snap: unable to find block device '%s'\n", target_name);
		return PTR_ERR(dev->sd_base_dev);
	}

	//check for target device gendisk
	printk(KERN_ERR "snap: get block device gendisk\n");
	if(!dev->sd_base_dev->bd_disk){
		printk(KERN_ERR "snap: block device did not have a gendisk\n");
		return -EFAULT;
	}

	//get target device queue
	printk(KERN_ERR "snap: get block device queue\n");
	q = bdev_get_queue(dev->sd_base_dev);
	if(!q){
		printk(KERN_ERR "snap: block device did not have a request queue\n");
		return -EFAULT;
	}

	//give our request queue the same properties as the target device
	printk(KERN_ERR "snap: set queue limits\n");
	dev->sd_gd->queue->limits.max_hw_sectors= q->limits.max_hw_sectors;
	dev->sd_gd->queue->limits.max_sectors = q->limits.max_sectors;
	dev->sd_gd->queue->limits.max_segment_size	= q->limits.max_segment_size;
	dev->sd_gd->queue->limits.max_segments	= q->limits.max_segments;
	dev->sd_gd->queue->limits.logical_block_size = 512;
	dev->sd_gd->queue->limits.physical_block_size = 512;
	set_bit(QUEUE_FLAG_NONROT, &dev->sd_gd->queue->queue_flags);
	set_capacity(dev->sd_gd, get_capacity(dev->sd_base_dev->bd_disk));
	dev->sd_size = get_capacity(dev->sd_base_dev->bd_disk);
	
	//name our gendisk
	printk(KERN_ERR "snap: name disk\n");
	snprintf (dev->sd_gd->disk_name, 32, SNAP_DEVICE_NAME);
	
	return 0;
}

static int setup_cow_file(struct snap_device *dev, const char *cow_name){
	struct file	*f;
	
	//create and open cow file
	printk(KERN_ERR "snap: create/open cow file '%s'\n", cow_name);
	f = filp_open(cow_name, O_RDWR | O_CREAT | O_LARGEFILE, 0);
	if (f == NULL || IS_ERR(f)) {
		printk(KERN_ERR "agent: open/create of cow file '%s' failed\n", cow_name);
		return PTR_ERR(f);
	}
	
	//check that cow file is a regular file
	printk(KERN_ERR "snap: check that cow file is regular file\n");
	if(!S_ISREG(f->f_dentry->d_inode->i_mode)){
		printk(KERN_ERR "agent: '%s' is not a regular file\n", cow_name);
		return -EINVAL;
	}
	
	//save file pointer to device struct
	dev->sd_cow_file = f;
	dev->sd_cow_inode = f->f_dentry->d_inode->i_ino;
	
	return 0;
}

//device initialization
static int setup_snap_device(struct snap_device *dev, const char *target_name, const char *cow_name){
	int ret;
	unsigned long bitmap_len;
	
	//allocate request queue
	printk(KERN_ERR "snap: allocate queue\n");
	dev->sd_queue = blk_alloc_queue(GFP_KERNEL);
	if (!dev->sd_queue){
		printk(KERN_ERR "snap: unable to allocate queue\n");
		return -ENOMEM;
	}

	//register request handler
	printk(KERN_ERR "snap: setup make request function\n");
	blk_queue_make_request(dev->sd_queue, snap_make_request);
	blk_queue_flush(dev->sd_queue, REQ_FLUSH | REQ_FUA);

	//allocate a gendisk struct
	printk(KERN_ERR "snap: allocate gendisk struct\n");
	dev->sd_gd = alloc_disk(1);
	if (!dev->sd_gd) {
		printk(KERN_ERR "snap: unable to allocate gendisk struct\n");
		return -ENOMEM;
	}

	//initialize gendisk struct
	printk(KERN_ERR "snap: initialize gendisk\n");
	dev->sd_gd->major = major;
	dev->sd_gd->first_minor = 0;
	dev->sd_gd->fops = &snap_ops;
	dev->sd_gd->queue = dev->sd_queue;
	dev->sd_gd->private_data = dev;
	dev->sd_gd->flags |= GENHD_FL_EXT_DEVT;

	//setup target device and adapt our gendisk to look like it
	printk(KERN_ERR "snap: setting up backing device\n");
	ret = setup_backing_device(dev, target_name);
	if(ret != 0){
		printk(KERN_ERR "snap: error setting up backing device\n");
		return ret;
	}
	
	//set up cow file
	printk(KERN_ERR "snap: setting up cow file\n");
	ret = setup_cow_file(dev, cow_name);
	if(ret != 0){
		printk(KERN_ERR "snap: error setting up cow file\n");
		return ret;
	}
	
	//allocate memory for the bitmap
	printk(KERN_ERR "snap: allocating memory for bitmap\n");
	bitmap_len = dev->sd_size/8;
	if(dev->sd_size % 8 != 0) bitmap_len++;
	dev->sd_bitmap = vzalloc(bitmap_len);
	if(!dev->sd_bitmap){
		printk(KERN_ERR "snap: could not allocate memory for bitmap\n");
		return -ENOMEM;
	}
	printk(KERN_ERR "snap: bitmap occupies %lu bytes at address %p\n", bitmap_len, dev->sd_bitmap);
	
	//initialize non-pointer fields
	printk(KERN_ERR "snap: initializing non-pointer fields\n");
	bio_list_init(&dev->sd_pending_bios);
	spin_lock_init(&dev->sd_bio_lock);
	mutex_init(&dev->sd_ctl_mutex);
	init_waitqueue_head(&dev->sd_bio_event);
	
	//start kthread for managing incoming bios
	printk(KERN_ERR "snap: creating kernel hread\n");
	dev->sd_kthread = kthread_run(snap_bio_thread, dev, "snap%d", dev->sd_minor);
	if(IS_ERR(dev->sd_kthread)){
		printk(KERN_ERR "snap: error creating kernel hread\n");
		return PTR_ERR(dev->sd_kthread);
	}
	
	//register gendisk with the kernel
	printk(KERN_ERR "snap: add disk\n");
	add_disk(dev->sd_gd);

	return 0;
}

static void debug_timer_cb(unsigned long data){
	printk(KERN_ERR "snap: writes - %d : %d\n", snap->writes_performed, snap->writes_intercepted);
	mod_timer(&timer, jiffies + msecs_to_jiffies(5000));
}

static void destroy_snap_device(struct snap_device *dev){
	//unallocate the gendisk and queue
	if(dev->sd_gd) {
		del_gendisk(dev->sd_gd);
		put_disk(dev->sd_gd);
	}
	if(dev->sd_queue) blk_cleanup_queue(dev->sd_queue);
	
	//put the target device back
	blkdev_put(dev->sd_base_dev, FMODE_READ);
	
	//close our cow file
	if(dev->sd_cow_file) filp_close(dev->sd_cow_file, 0);
	
	//stop our kernel thread
	kthread_stop(dev->sd_kthread);
	
	//free our bitmap
	if(dev->sd_bitmap) vfree(dev->sd_bitmap);
	
	//free our device
	kfree(dev);
}

/************************MODULE SETUP AND DESTROY************************/

static int __init snap_init(void){
	int ret;

	//allocate struct
	printk(KERN_ERR "snap: allocate device struct\n");
	snap = kzalloc(sizeof(struct snap_device), GFP_KERNEL);
	if(!snap){
		printk(KERN_ERR "snap: unable to allocate device struct\n");
		return -ENOMEM;
	}

	//get a major number for the driver
	printk(KERN_ERR "snap: get major number\n");
	major = register_blkdev(0, SNAP_DEVICE_NAME);
	if(major <= 0){
		printk(KERN_ERR "snap: unable to get major number\n");
		return -EBUSY;
	}

	//setup device
	printk(KERN_ERR "snap: setup snap device - %p %s\n", snap, TARGET_NAME);
	ret = setup_snap_device(snap, TARGET_NAME, COW_FILE_NAME);
	if(ret != 0){
		printk(KERN_ERR "snap: error setting up snap device\n");
		unregister_blkdev(major, SNAP_DEVICE_NAME);
		return ret;
	}
	
	//setup tracing
	printk(KERN_ERR "snap: setting up tracing\n");
	ret = register_trace_block_bio_queue(on_request, NULL);
	if(ret){
		printk(KERN_ERR "snap: error setting up tracing\n");
		return ret;
	}
	
	//setup timer for debugging
	printk(KERN_ERR "snap: setting up debug timer\n");
	setup_timer(&timer, debug_timer_cb, 0);
	ret = mod_timer(&timer, jiffies + msecs_to_jiffies(5000));
	if(ret){
		printk(KERN_ERR "snap: error setting up debug timer\n");
		return ret;
	}
	return 0;
}

static void __exit snap_exit(void){
	//destroy our device
	destroy_snap_device(snap);
	
	//unregister our block device driver
	unregister_blkdev(major, SNAP_DEVICE_NAME);
	
	//stop tracing
	unregister_trace_block_bio_queue(on_request, NULL);
	
	//free our debug timer
	del_timer(&timer);
}

//module stuff
MODULE_LICENSE("GPL");
module_init(snap_init);
module_exit(snap_exit);