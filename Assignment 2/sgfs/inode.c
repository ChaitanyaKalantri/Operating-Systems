/*
 * Copyright (c) 1998-2015 Erez Zadok
 * Copyright (c) 2009	   Shrikar Archak
 * Copyright (c) 2003-2015 Stony Brook University
 * Copyright (c) 2003-2015 The Research Foundation of SUNY
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/pagemap.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/crypto.h>
#include <linux/scatterlist.h>
#include <linux/namei.h>
#include <linux/stat.h>
#include <linux/path.h>
#include <linux/err.h>
#include <crypto/hash.h>
#define PAD 16
#define HASHLEN 16
#define AES_KEY_SIZE 16

#define BLOCK_READ_SIZE PAGE_SIZE
#define AES_BLOCK_SIZE PAGE_SIZE
#define ENCRYPT 1
#define DECRYPT 0
#define TASK_MASK 0x0001
#include "sgfs.h"

extern char key_val[20];
extern char mainPath[50];


static struct crypto_blkcipher *ceph_crypto_alloc_cipher(void){
    return crypto_alloc_blkcipher("cbc(aes)", 0, CRYPTO_ALG_ASYNC);
}
static const u8 *aes_iv = "cephsageyudagreg";
//extern int (*function_pointer)(char*, char*, char*, int, int);

/*
 * The locking rules in sgfs_rename are complex.  We could use a simpler
 * superblock-level name-space lock for renames and copy-ups.
 */


static void printData(unsigned char *src, int len, char *name)
{
	int i=0;
	printk("Printing for %s  and len %d\n", name, len);
	for (i=0; i < len; i++) {
		printk("%x ", src[i]);
	}
	printk("\n");

}



int ceph_aes_encrypt(const void *key, int key_len, void *dst, size_t *dst_len,
                      const void *src, size_t src_len){
    
    struct scatterlist sg_in[2], sg_out[1];
    struct crypto_blkcipher *tfm = ceph_crypto_alloc_cipher();
    struct blkcipher_desc desc = { .tfm = tfm, .flags = 0 };
    int ret;
    void *iv;
    int ivsize;
    size_t zero_padding = (0x10 - (src_len & 0x0f));
    char pad[16];
    
    if (IS_ERR(tfm))
        return PTR_ERR(tfm);
    
    memset(pad, zero_padding, zero_padding);
    
    *dst_len = src_len + zero_padding;
    crypto_blkcipher_setkey((void *)tfm, key, key_len);
    sg_init_table(sg_in, 2);
    sg_set_buf(&sg_in[0], src, src_len);
    sg_set_buf(&sg_in[1], pad, zero_padding);
    sg_init_table(sg_out, 1);
    sg_set_buf(sg_out, dst, *dst_len);
    iv = crypto_blkcipher_crt(tfm)->iv;
    ivsize = crypto_blkcipher_ivsize(tfm); 
    memcpy(iv, aes_iv, ivsize);
    
    ret = crypto_blkcipher_encrypt(&desc, sg_out, sg_in,
                                      src_len + zero_padding);
    crypto_free_blkcipher(tfm);
    if (ret < 0)
        pr_err("ceph_aes_crypt failed %d\n", ret);

    return 0;
}


static int sgfs_rename(struct inode *old_dir, struct dentry *old_dentry,
			 struct inode *new_dir, struct dentry *new_dentry)
{
	int err = 0;
	struct dentry *lower_old_dentry = NULL;
	struct dentry *lower_new_dentry = NULL;
	struct dentry *lower_old_dir_dentry = NULL;
	struct dentry *lower_new_dir_dentry = NULL;
	struct dentry *trap = NULL;
	struct path lower_old_path, lower_new_path;
	printk("1.....\n");
	sgfs_get_lower_path(old_dentry, &lower_old_path);
	printk("1.....2\n");
	sgfs_get_lower_path(new_dentry, &lower_new_path);
	printk("1.....3\n");
	lower_old_dentry = lower_old_path.dentry;
	lower_new_dentry = lower_new_path.dentry;
	lower_old_dir_dentry = dget_parent(lower_old_dentry);
	lower_new_dir_dentry = dget_parent(lower_new_dentry);
	printk("1.....4\n");
	trap = lock_rename(lower_old_dir_dentry, lower_new_dir_dentry);
	/* source should not be ancestor of target */
	if (trap == lower_old_dentry) {
		err = -EINVAL;
		goto out;
	}
	/* target should not be ancestor of source */
	if (trap == lower_new_dentry) {
		err = -ENOTEMPTY;
		goto out;
	}

	err = vfs_rename(d_inode(lower_old_dir_dentry), lower_old_dentry,
			 d_inode(lower_new_dir_dentry), lower_new_dentry,
			 NULL, 0);
	if (err)
		goto out;

	fsstack_copy_attr_all(new_dir, d_inode(lower_new_dir_dentry));
	fsstack_copy_inode_size(new_dir, d_inode(lower_new_dir_dentry));
	if (new_dir != old_dir) {
		fsstack_copy_attr_all(old_dir,
				      d_inode(lower_old_dir_dentry));
		fsstack_copy_inode_size(old_dir,
					d_inode(lower_old_dir_dentry));
	}

out:
	unlock_rename(lower_old_dir_dentry, lower_new_dir_dentry);
	dput(lower_old_dir_dentry);
	dput(lower_new_dir_dentry);
	sgfs_put_lower_path(old_dentry, &lower_old_path);
	sgfs_put_lower_path(new_dentry, &lower_new_path);
	return err;
}

static int sgfs_create(struct inode *dir, struct dentry *dentry,
			 umode_t mode, bool want_excl)
{
	int err;
	struct dentry *lower_dentry;
	struct dentry *lower_parent_dentry = NULL;
	struct path lower_path;

	sgfs_get_lower_path(dentry, &lower_path);
	lower_dentry = lower_path.dentry;
	lower_parent_dentry = lock_parent(lower_dentry);
	
	printk("I am in the sgfs_create\n");
	err = vfs_create(d_inode(lower_parent_dentry), lower_dentry, mode,
			 want_excl);
	if (err)
		goto out;
	err = sgfs_interpose(dentry, dir->i_sb, &lower_path);
	if (err)
		goto out;
	fsstack_copy_attr_times(dir, sgfs_lower_inode(dir));
	fsstack_copy_inode_size(dir, d_inode(lower_parent_dentry));

out:
	unlock_dir(lower_parent_dentry);
	sgfs_put_lower_path(dentry, &lower_path);
	return err;
}

static int sgfs_link(struct dentry *old_dentry, struct inode *dir,
		       struct dentry *new_dentry)
{
	struct dentry *lower_old_dentry;
	struct dentry *lower_new_dentry;
	struct dentry *lower_dir_dentry;
	u64 file_size_save;
	int err;
	struct path lower_old_path, lower_new_path;

	file_size_save = i_size_read(d_inode(old_dentry));
	sgfs_get_lower_path(old_dentry, &lower_old_path);
	sgfs_get_lower_path(new_dentry, &lower_new_path);
	lower_old_dentry = lower_old_path.dentry;
	lower_new_dentry = lower_new_path.dentry;
	lower_dir_dentry = lock_parent(lower_new_dentry);
	
	printk("I am in the sgfs_link\n");
	err = vfs_link(lower_old_dentry, d_inode(lower_dir_dentry),
		       lower_new_dentry, NULL);
	if (err || !d_inode(lower_new_dentry))
		goto out;

	err = sgfs_interpose(new_dentry, dir->i_sb, &lower_new_path);
	if (err)
		goto out;
	fsstack_copy_attr_times(dir, d_inode(lower_new_dentry));
	fsstack_copy_inode_size(dir, d_inode(lower_new_dentry));
	set_nlink(d_inode(old_dentry),
		  sgfs_lower_inode(d_inode(old_dentry))->i_nlink);
	i_size_write(d_inode(new_dentry), file_size_save);
out:
	unlock_dir(lower_dir_dentry);
	sgfs_put_lower_path(old_dentry, &lower_old_path);
	sgfs_put_lower_path(new_dentry, &lower_new_path);
	return err;
}


int sgfs_unlink(struct inode *dir, struct dentry *dentry)
{
	char k_keybuf[30];// = "ENCRYPT";
	//printk("strlen(key_val) is %d\n", strlen(key_val));
	//printk("strlen(k_keybuf) is %d\n", strlen(k_keybuf));	
	int flag = 0;
	if(strlen(key_val) == 0)
        {
		flag = 1;
		printk("The keyval is NULL\n");
        }
	else
	{	
		strcpy(k_keybuf, key_val);
	}
	

	//strcpy(k_keybuf, key_val);

        char *k_tempdst = NULL ;
        //char *k_temp2dst = NULL ;
        size_t k_dstlen; // k_dst2len;
	
	int keylen = strlen(k_keybuf);        
	int ret = 0, err=0;
       	char *filp0_buf = NULL; 
	struct file *filp1 = NULL, *filp0 = NULL;
	int f_readBytes, f_readLen;	
	mm_segment_t oldfs;
	loff_t f_readOffset = 0, f_writeBytes = 0;
	
	char *test = NULL, *p = NULL, *pathname = NULL, *original = NULL, *tempFile = NULL;

	struct dentry *lower_dentry = NULL;
	struct inode *lower_dir_inode = sgfs_lower_inode(dir);
	struct dentry *lower_dir_dentry = NULL;
	struct path lower_path;

	const struct cred *cred = current_cred();
    	//char c[20];
    	//strcpy(c, cred->uid);
	
	struct timeval t;
	struct tm broken;
	do_gettimeofday(&t);
	time_to_tm(t.tv_sec, 0, &broken);	


	sgfs_get_lower_path(dentry, &lower_path);
	lower_dentry = lower_path.dentry;
	dget(lower_dentry);	

	k_tempdst = kmalloc(PAGE_SIZE, GFP_KERNEL);
        if (!k_tempdst)
        {
                printk("Error\n");
                return err;
        }
	
	//k_temp2dst = kmalloc(PAGE_SIZE, GFP_KERNEL);
        //if (!k_temp2dst)
        //{
        //        printk("Error\n");
        //        return err;
        //}
	
	printk("lower path %s\n",lower_dentry->d_parent->d_iname);
	tempFile = kmalloc(PATH_MAX, GFP_KERNEL);
        if (!tempFile)
        {
                printk("Error\n");
                return err;
        }
	
	printk("mainPath is %s\n", mainPath);
        sprintf(tempFile, "%ld-%02d-%02d-%02d:%02d-%s" , broken.tm_year+1900, broken.tm_mon+1, broken.tm_mday, broken.tm_hour, broken.tm_min, lower_dentry->d_iname);
        printk("File name is %s\n", tempFile);

	
	pathname = kmalloc(PATH_MAX+11, GFP_KERNEL);
	if (!pathname)
	{
		printk("Error\n");
		return err;
	}
	p = d_path(&lower_path, pathname, PATH_MAX+11);
	if (IS_ERR(p))
	{ /* Should never happen since we send PATH_MAX */
		kfree(pathname);
		return err;
	}
	printk("lower path absolute %s\n",p);
	
	original= kmalloc(PATH_MAX,GFP_KERNEL);
	if(!original)
		goto EXIT;

	strcpy(original,p);
	
	//strcpy(p, mainPath);
	//strcpy(p, ".sg/");	
	//strcat(p, tempFile);	

	test = kmalloc(PATH_MAX, GFP_KERNEL);
        if (!test)
        {
                printk("Error\n");
                return err;
        }

	strcpy(test, mainPath);
	printk("Test1 is %s\n", test);

	strcat(test, "/.sg/");
	
	printk("Test2 is %s\n", test);

	strcat(test, tempFile);
	printk("Test3 is %s\n", test);

	strcat(test, ".enc");
	printk("Test4 is %s\n", test);
	//sprintf(test, "%s%s" , mainPath, ".sg" );
	//printk("Test is %s\n", test);	

	sprintf(test, "%s-%ld", test, cred->uid);
	//sprintf(test, "%04ld-%s", cred->uid, test);
	printk("Test5 is %s\n", test);

	//strcpy(p, tempFile);
	strcat(p, ".enc");
	//printk("p is %s\n", p);

	/*
	tempFile = kmalloc(PATH_MAX, GFP_KERNEL);
        if (!tempFile)
        {
                printk("Error\n");
                return err;
        }

	printk("lower path %s\n",lower_dentry->d_iname);
	sprintf(tempFile, "%ld-%d-%d-%d:%d-%s" , broken.tm_year, broken.tm_mon, broken.tm_mday, broken.tm_hour, broken.tm_min, lower_dentry->d_iname);
	printk("File name is %s", tempFile);
	*/

	filp0 = filp_open(original, O_RDONLY, 0664);
	if(!filp0 || IS_ERR(filp0))
        {
                err = -ENOENT;
                goto EXIT;
        }

	printk("Test before inserting %s\n", test);	
	filp1 = filp_open(test, O_CREAT|O_WRONLY, 0664);
	if(!filp1 || IS_ERR(filp1))
        {
                err = -ENOENT;
                goto EXIT;
        }

	filp0_buf = (char *)kmalloc(PAGE_SIZE, GFP_KERNEL);	
	if (!filp0_buf){
                printk("No memory for file buffer 1\n");
                err = -ENOMEM;
                goto EXIT;
        }
		
	oldfs = get_fs();
    	set_fs(get_ds());
	f_readLen = filp0->f_inode->i_size;
	printk("Size of the fReadLen is %d \n", f_readLen);
	
	while(1)
	{
		f_readBytes = vfs_read(filp0, filp0_buf, PAGE_SIZE, &f_readOffset);
		if (f_readBytes < 0)
		{
			printk("No data\n");
			set_fs(oldfs);
            		goto EXIT;
        	}
		else if(f_readBytes == 0)
		{
			goto EXIT_PREV;
		}
		else
		{
			//printk("The data read is %s\n", filp0_buf);
	
	//set_fs(oldfs);
		
	if(flag == 0)
        {
	ret = ceph_aes_encrypt(k_keybuf, keylen, k_tempdst, &k_dstlen, filp0_buf, f_readBytes);
        //printk("k_dstlen = %d\n",k_dstlen);
	

	//printData(k_tempdst, k_dstlen, "k_tempdst");
	
        if(ret < 0)
	{
		printk("I am in ret < 0\n");
                set_fs(oldfs);
                ret = -EPERM;
                goto EXIT;
	}
	//vfs_write(filp1, k_tempdst, k_dstlen, &filp1->f_pos);
	ret = vfs_write(filp1, k_tempdst, k_dstlen, &f_writeBytes);        
	//printk("Write bytes is %d\n", ret);
		
	//ret = ceph_aes_decrypt(k_keybuf, keylen, k_temp2dst, &k_dstlen, k_tempdst, k_dstlen);	// Changed &k_dst2len to &k_dstlen
        //printk("%d\n",k_dstlen);
        if (ret < 0)
	{
		set_fs(oldfs);	
		ret = -EPERM;
		goto out;
                
	}
	/*
	printData(k_temp2dst, k_dstlen, "k_temp2dst");
	//printk("Decrypted data is %s\n", k_temp2dst);
	*/
	}
	else if(flag == 1)
	{
		ret = vfs_write(filp1, filp0_buf, f_readBytes, &f_writeBytes);	
		if (ret < 0)
        	{
			set_fs(oldfs);
                	ret = -EPERM;
                	goto out;
        	}
	}
    }
  }

	EXIT_PREV:
	set_fs(oldfs);
	lower_dir_dentry = lock_parent(lower_dentry);
	printk("Lower_dir_entry is %p\n", lower_dir_dentry);	

	if(filp0 != NULL)
                filp_close(filp0, NULL);
        if(filp1 != NULL)
                filp_close(filp1, NULL);
	
	printk("lower_dentry: %s \n lower_dir_inode: %s", lower_dentry->d_iname);
	err = vfs_unlink(lower_dir_inode, lower_dentry, NULL);
	printk("I have completed unlinking\n");	
	
	
	if (err == -EBUSY && lower_dentry->d_flags & DCACHE_NFSFS_RENAMED)
		err = 0;
	if (err)
		goto out;
	fsstack_copy_attr_times(dir, lower_dir_inode);
	fsstack_copy_inode_size(dir, lower_dir_inode);
	set_nlink(d_inode(dentry),
			  sgfs_lower_inode(d_inode(dentry))->i_nlink);
	d_inode(dentry)->i_ctime = dir->i_ctime;
	d_drop(dentry); // this is needed, else LTP fails (VFS won't do it) 

	out:
	printk("Above unlock_dir %p\n", lower_dir_dentry);
	
	unlock_dir(lower_dir_dentry);
	printk("Above dput %p\n", lower_dentry);
	dput(lower_dentry);
	printk("Above sgfs_put_lower_path %p\n", dentry);
	sgfs_put_lower_path(dentry, &lower_path);	
	printk("Above EXIT\n");

	EXIT:
	if(filp0 != NULL)
		filp_close(filp0, NULL);
	if(filp1 != NULL)
		filp_close(filp1, NULL);
	if(filp0_buf != NULL)
		kfree(filp0_buf);
	/*
	filp2 = filp_open(original, O_RDONLY, 0664);
        if(!filp2 || IS_ERR(filp2))
        {
                err = -ENOENT;
                goto EXIT_NEW;
        }
	*/
	
	//filp3 = filp_open();



	return err;
}


static int sgfs_symlink(struct inode *dir, struct dentry *dentry,
			  const char *symname)
{
	int err;
	struct dentry *lower_dentry;
	struct dentry *lower_parent_dentry = NULL;
	struct path lower_path;

	sgfs_get_lower_path(dentry, &lower_path);
	lower_dentry = lower_path.dentry;
	lower_parent_dentry = lock_parent(lower_dentry);

	err = vfs_symlink(d_inode(lower_parent_dentry), lower_dentry, symname);
	if (err)
		goto out;
	err = sgfs_interpose(dentry, dir->i_sb, &lower_path);
	if (err)
		goto out;
	fsstack_copy_attr_times(dir, sgfs_lower_inode(dir));
	fsstack_copy_inode_size(dir, d_inode(lower_parent_dentry));

out:
	unlock_dir(lower_parent_dentry);
	sgfs_put_lower_path(dentry, &lower_path);
	return err;
}

static int sgfs_mkdir(struct inode *dir, struct dentry *dentry, umode_t mode)
{
	int err;
	struct dentry *lower_dentry;
	struct dentry *lower_parent_dentry = NULL;
	struct path lower_path;

	sgfs_get_lower_path(dentry, &lower_path);
	lower_dentry = lower_path.dentry;
	lower_parent_dentry = lock_parent(lower_dentry);

	err = vfs_mkdir(d_inode(lower_parent_dentry), lower_dentry, mode);
	if (err)
		goto out;

	err = sgfs_interpose(dentry, dir->i_sb, &lower_path);
	if (err)
		goto out;

	fsstack_copy_attr_times(dir, sgfs_lower_inode(dir));
	fsstack_copy_inode_size(dir, d_inode(lower_parent_dentry));
	/* update number of links on parent directory */
	set_nlink(dir, sgfs_lower_inode(dir)->i_nlink);

out:
	unlock_dir(lower_parent_dentry);
	sgfs_put_lower_path(dentry, &lower_path);
	return err;
}

static int sgfs_rmdir(struct inode *dir, struct dentry *dentry)
{
	struct dentry *lower_dentry;
	struct dentry *lower_dir_dentry;
	int err;
	struct path lower_path;

	sgfs_get_lower_path(dentry, &lower_path);
	lower_dentry = lower_path.dentry;
	lower_dir_dentry = lock_parent(lower_dentry);

	err = vfs_rmdir(d_inode(lower_dir_dentry), lower_dentry);
	if (err)
		goto out;

	d_drop(dentry);	/* drop our dentry on success (why not VFS's job?) */
	if (d_inode(dentry))
		clear_nlink(d_inode(dentry));
	fsstack_copy_attr_times(dir, d_inode(lower_dir_dentry));
	fsstack_copy_inode_size(dir, d_inode(lower_dir_dentry));
	set_nlink(dir, d_inode(lower_dir_dentry)->i_nlink);

out:
	unlock_dir(lower_dir_dentry);
	sgfs_put_lower_path(dentry, &lower_path);
	return err;
}

static int sgfs_mknod(struct inode *dir, struct dentry *dentry, umode_t mode,
			dev_t dev)
{
	int err;
	struct dentry *lower_dentry;
	struct dentry *lower_parent_dentry = NULL;
	struct path lower_path;

	sgfs_get_lower_path(dentry, &lower_path);
	lower_dentry = lower_path.dentry;
	lower_parent_dentry = lock_parent(lower_dentry);

	err = vfs_mknod(d_inode(lower_parent_dentry), lower_dentry, mode, dev);
	if (err)
		goto out;

	err = sgfs_interpose(dentry, dir->i_sb, &lower_path);
	if (err)
		goto out;
	fsstack_copy_attr_times(dir, sgfs_lower_inode(dir));
	fsstack_copy_inode_size(dir, d_inode(lower_parent_dentry));

out:
	unlock_dir(lower_parent_dentry);
	sgfs_put_lower_path(dentry, &lower_path);
	return err;
}


static int sgfs_readlink(struct dentry *dentry, char __user *buf, int bufsiz)
{
	int err;
	struct dentry *lower_dentry;
	struct path lower_path;

	sgfs_get_lower_path(dentry, &lower_path);
	lower_dentry = lower_path.dentry;
	if (!d_inode(lower_dentry)->i_op ||
	    !d_inode(lower_dentry)->i_op->readlink) {
		err = -EINVAL;
		goto out;
	}

	err = d_inode(lower_dentry)->i_op->readlink(lower_dentry,
						    buf, bufsiz);
	if (err < 0)
		goto out;
	fsstack_copy_attr_atime(d_inode(dentry), d_inode(lower_dentry));

out:
	sgfs_put_lower_path(dentry, &lower_path);
	return err;
}

static const char *sgfs_get_link(struct dentry *dentry, struct inode *inode,
				   struct delayed_call *done)
{
	char *buf;
	int len = PAGE_SIZE, err;
	mm_segment_t old_fs;

	if (!dentry)
		return ERR_PTR(-ECHILD);

	/* This is freed by the put_link method assuming a successful call. */
	buf = kmalloc(len, GFP_KERNEL);
	if (!buf) {
		buf = ERR_PTR(-ENOMEM);
		return buf;
	}

	/* read the symlink, and then we will follow it */
	old_fs = get_fs();
	set_fs(KERNEL_DS);
	err = sgfs_readlink(dentry, buf, len);
	set_fs(old_fs);
	if (err < 0) {
		kfree(buf);
		buf = ERR_PTR(err);
	} else {
		buf[err] = '\0';
	}
	set_delayed_call(done, kfree_link, buf);
	return buf;
}

static int sgfs_permission(struct inode *inode, int mask)
{
	struct inode *lower_inode;
	int err;

	lower_inode = sgfs_lower_inode(inode);
	err = inode_permission(lower_inode, mask);
	return err;
}

static int sgfs_setattr(struct dentry *dentry, struct iattr *ia)
{
	int err;
	struct dentry *lower_dentry;
	struct inode *inode;
	struct inode *lower_inode;
	struct path lower_path;
	struct iattr lower_ia;

	inode = d_inode(dentry);

	/*
	 * Check if user has permission to change inode.  We don't check if
	 * this user can change the lower inode: that should happen when
	 * calling notify_change on the lower inode.
	 */
	err = inode_change_ok(inode, ia);
	if (err)
		goto out_err;

	sgfs_get_lower_path(dentry, &lower_path);
	lower_dentry = lower_path.dentry;
	lower_inode = sgfs_lower_inode(inode);

	/* prepare our own lower struct iattr (with the lower file) */
	memcpy(&lower_ia, ia, sizeof(lower_ia));
	if (ia->ia_valid & ATTR_FILE)
		lower_ia.ia_file = sgfs_lower_file(ia->ia_file);

	/*
	 * If shrinking, first truncate upper level to cancel writing dirty
	 * pages beyond the new eof; and also if its' maxbytes is more
	 * limiting (fail with -EFBIG before making any change to the lower
	 * level).  There is no need to vmtruncate the upper level
	 * afterwards in the other cases: we fsstack_copy_inode_size from
	 * the lower level.
	 */
	if (ia->ia_valid & ATTR_SIZE) {
		err = inode_newsize_ok(inode, ia->ia_size);
		if (err)
			goto out;
		truncate_setsize(inode, ia->ia_size);
	}

	/*
	 * mode change is for clearing setuid/setgid bits. Allow lower fs
	 * to interpret this in its own way.
	 */
	if (lower_ia.ia_valid & (ATTR_KILL_SUID | ATTR_KILL_SGID))
		lower_ia.ia_valid &= ~ATTR_MODE;

	/* notify the (possibly copied-up) lower inode */
	/*
	 * Note: we use d_inode(lower_dentry), because lower_inode may be
	 * unlinked (no inode->i_sb and i_ino==0.  This happens if someone
	 * tries to open(), unlink(), then ftruncate() a file.
	 */
	inode_lock(d_inode(lower_dentry));
	err = notify_change(lower_dentry, &lower_ia, /* note: lower_ia */
			    NULL);
	inode_unlock(d_inode(lower_dentry));
	if (err)
		goto out;

	/* get attributes from the lower inode */
	fsstack_copy_attr_all(inode, lower_inode);
	/*
	 * Not running fsstack_copy_inode_size(inode, lower_inode), because
	 * VFS should update our inode size, and notify_change on
	 * lower_inode should update its size.
	 */

out:
	sgfs_put_lower_path(dentry, &lower_path);
out_err:
	return err;
}

static int sgfs_getattr(struct vfsmount *mnt, struct dentry *dentry,
			  struct kstat *stat)
{
	int err;
	struct kstat lower_stat;
	struct path lower_path;

	sgfs_get_lower_path(dentry, &lower_path);
	err = vfs_getattr(&lower_path, &lower_stat);
	if (err)
		goto out;
	fsstack_copy_attr_all(d_inode(dentry),
			      d_inode(lower_path.dentry));
	generic_fillattr(d_inode(dentry), stat);
	stat->blocks = lower_stat.blocks;
out:
	sgfs_put_lower_path(dentry, &lower_path);
	return err;
}

static int
sgfs_setxattr(struct dentry *dentry, const char *name, const void *value,
		size_t size, int flags)
{
	int err; struct dentry *lower_dentry;
	struct path lower_path;

	sgfs_get_lower_path(dentry, &lower_path);
	lower_dentry = lower_path.dentry;
	if (!d_inode(lower_dentry)->i_op->setxattr) {
		err = -EOPNOTSUPP;
		goto out;
	}
	err = vfs_setxattr(lower_dentry, name, value, size, flags);
	if (err)
		goto out;
	fsstack_copy_attr_all(d_inode(dentry),
			      d_inode(lower_path.dentry));
out:
	sgfs_put_lower_path(dentry, &lower_path);
	return err;
}

static ssize_t
sgfs_getxattr(struct dentry *dentry, const char *name, void *buffer,
		size_t size)
{
	int err;
	struct dentry *lower_dentry;
	struct path lower_path;

	sgfs_get_lower_path(dentry, &lower_path);
	lower_dentry = lower_path.dentry;
	if (!d_inode(lower_dentry)->i_op->getxattr) {
		err = -EOPNOTSUPP;
		goto out;
	}
	err = vfs_getxattr(lower_dentry, name, buffer, size);
	if (err)
		goto out;
	fsstack_copy_attr_atime(d_inode(dentry),
				d_inode(lower_path.dentry));
out:
	sgfs_put_lower_path(dentry, &lower_path);
	return err;
}

static ssize_t
sgfs_listxattr(struct dentry *dentry, char *buffer, size_t buffer_size)
{
	int err;
	struct dentry *lower_dentry;
	struct path lower_path;

	sgfs_get_lower_path(dentry, &lower_path);
	lower_dentry = lower_path.dentry;
	if (!d_inode(lower_dentry)->i_op->listxattr) {
		err = -EOPNOTSUPP;
		goto out;
	}
	err = vfs_listxattr(lower_dentry, buffer, buffer_size);
	if (err)
		goto out;
	fsstack_copy_attr_atime(d_inode(dentry),
				d_inode(lower_path.dentry));
out:
	sgfs_put_lower_path(dentry, &lower_path);
	return err;
}

static int
sgfs_removexattr(struct dentry *dentry, const char *name)
{
	int err;
	struct dentry *lower_dentry;
	struct path lower_path;

	sgfs_get_lower_path(dentry, &lower_path);
	lower_dentry = lower_path.dentry;
	if (!d_inode(lower_dentry)->i_op ||
	    !d_inode(lower_dentry)->i_op->removexattr) {
		err = -EINVAL;
		goto out;
	}
	err = vfs_removexattr(lower_dentry, name);
	if (err)
		goto out;
	fsstack_copy_attr_all(d_inode(dentry),
			      d_inode(lower_path.dentry));
out:
	sgfs_put_lower_path(dentry, &lower_path);
	return err;
}
const struct inode_operations sgfs_symlink_iops = {
	.readlink	= sgfs_readlink,
	.permission	= sgfs_permission,
	.setattr	= sgfs_setattr,
	.getattr	= sgfs_getattr,
	.get_link	= sgfs_get_link,
	.setxattr	= sgfs_setxattr,
	.getxattr	= sgfs_getxattr,
	.listxattr	= sgfs_listxattr,
	.removexattr	= sgfs_removexattr,
};

const struct inode_operations sgfs_dir_iops = {
	.create		= sgfs_create,
	.lookup		= sgfs_lookup,
	.link		= sgfs_link,
	.unlink		= sgfs_unlink,
	.symlink	= sgfs_symlink,
	.mkdir		= sgfs_mkdir,
	.rmdir		= sgfs_rmdir,
	.mknod		= sgfs_mknod,
	.rename		= sgfs_rename,
	.permission	= sgfs_permission,
	.setattr	= sgfs_setattr,
	.getattr	= sgfs_getattr,
	.setxattr	= sgfs_setxattr,
	.getxattr	= sgfs_getxattr,
	.listxattr	= sgfs_listxattr,
	.removexattr	= sgfs_removexattr,
};

const struct inode_operations sgfs_main_iops = {
	.permission	= sgfs_permission,
	.setattr	= sgfs_setattr,
	.getattr	= sgfs_getattr,
	.setxattr	= sgfs_setxattr,
	.getxattr	= sgfs_getxattr,
	.listxattr	= sgfs_listxattr,
	.removexattr	= sgfs_removexattr,
};
