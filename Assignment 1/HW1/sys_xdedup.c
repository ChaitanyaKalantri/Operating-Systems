#include <linux/linkage.h>
#include <linux/moduleloader.h>
#include <linux/kernel.h> 
#include <linux/init.h> 
#include <linux/module.h> 
#include <linux/syscalls.h> 
#include <linux/fcntl.h> 
#include <asm/uaccess.h>
#include <linux/types.h>
#include <linux/fs.h>
#include <linux/string.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/mount.h>
#include <linux/path.h>
#include <linux/namei.h>
#include<linux/time.h>
#include "xdedup_args.h"
//#include "bit_map.h"
#define CHUNK PAGE_SIZE

asmlinkage extern long (*sysptr)(void *arg);

int checkFileSame(const char *infile1, const char *infile2)
{
        struct path in, out;
        int check = 0;

    mm_segment_t old_fs;
    old_fs = get_fs();
    set_fs(KERNEL_DS);

    check = kern_path(infile1,LOOKUP_FOLLOW,&in);
    if(check != 0){
        goto EXIT_check;
    }
    check = kern_path(infile2,LOOKUP_FOLLOW,&out);
    if(check != 0 && check != -ENOENT){
        goto EXIT_check;
    }
   if((strcmp(in.dentry->d_inode->i_sb->s_id, out.dentry->d_inode->i_sb->s_id) == 0)
       && (in.dentry->d_inode->i_ino == out.dentry->d_inode->i_ino)){
       check = 1;
       goto EXIT_check;
    }
    check = 0;
EXIT_check:
    set_fs(old_fs);
    return check;
}



int wrapfs_read_file(char *outfile, const char *infile1, const char *infile2, int flag, bool d_val, bool fileValid, char* outfile1)
{
    if(flag == 3 || d_val == true)
    	printk("I am in the wrapfs_read_file\n");
    struct file *filp1;
    struct inode *inode1;
    mm_segment_t oldfs1;
    int bytes1;
    char *buf1;
    int fsize1;
    int i=0, j=0;
    struct file *filp2;
    struct inode *inode2;
    int bytes2;
    char *buf2;
    int fsize2;
    int ret = 0;
    int error = 0;
    struct file *filp3;
    struct path path1;
    struct path path2;
    struct path path3;
    struct dentry *newdentry;
    char *filename;
    struct file *filp4;
    char *buf3 = NULL;
    char *buf4 = NULL;	
	
    error = checkFileSame(infile1, infile2);
    if(error == 1)
    {
        error = -EINVAL;
        return error;
    }
    else if(error < 0)
    {
        return error;
    }

    if(flag == 1)
    {
        filp3 = filp_open(outfile, O_WRONLY, &path2);
        if (!filp3 || IS_ERR(filp3)) {
        //printk("wrapfs_read_file err %d\n", (int) PTR_ERR(filp3));
        error = -1;  
        goto exit1;
        }
        filp3->f_pos = 0;
    }

    filp1 = filp_open(infile1, O_RDONLY, 0);
    if (!filp1 || IS_ERR(filp1)) {
        //printk("wrapfs_read_file err %d\n", (int) PTR_ERR(filp1));
        error = -1;  
        goto exit1;
    }

    filp2 = filp_open(infile2, O_RDONLY, 0);
    if (!filp2 || IS_ERR(filp2)) {
        //printk("wrapfs_read_file err %d\n", (int) PTR_ERR(filp2));
        error = -1;  
        goto exit1;
    }

    if(flag == 3 || d_val == true)
    	printk("File Checking Complete\n");

    inode1=filp1->f_inode;
    fsize1=inode1->i_size;

    inode2=filp2->f_inode;
    fsize2=inode2->i_size;

    buf1=(char *) kmalloc(sizeof(char)*CHUNK,GFP_ATOMIC);
    buf2=(char *) kmalloc(sizeof(char)*CHUNK,GFP_ATOMIC);
    filp1->f_pos = 0;   
    filp2->f_pos = 0;
	//printk("UP buf1-> %p\n", buf1);
        //printk("UP buf2->%p\n", buf2);
    
    oldfs1 = get_fs();
    set_fs(KERNEL_DS);

    if(flag == 1)
    {
	ret = 0;
	if(d_val == true)
		printk("Enteredt into the p functionality\n");
        for(i=0; i<fsize1; i+= CHUNK)
        {
            bytes1 =  vfs_read(filp1, buf1, CHUNK, &filp1->f_pos);
            bytes2 =  vfs_read(filp2, buf2, CHUNK, &filp2->f_pos);
	    //CHUNK = min(CHUNK, fsize1-ret);
            for(j=0; j<CHUNK; j++)
            {
		if(ret >= fsize1 || ret >= fsize2)
		{
			goto exit;
		}
		if(buf1[j] == NULL || buf2[j] == NULL)
			goto exit;		
		  //printk("buf1-> %p\n", buf1);
		  //printk("buf2->%p\n", buf2);
                  if(buf1[j] != buf2[j])
                  {
                    error = 0;
                    ret += 0;
                    goto exit;
                  }
                  else
                  {
                    ret += vfs_write(filp3, &buf1[j], 1, &filp3->f_pos);
                  }
            }
		
	    if(buf1 != NULL)
            	kfree(buf1);
	    if(buf2 != NULL)
            	kfree(buf2);
	 
	if(j >= fsize1-1)	
	    goto exit;
        }	
    }
   	    
	if(buf1 != NULL)
               kfree(buf1);
        if(buf2 != NULL)
               kfree(buf2);
 
	buf3=(char *) kmalloc(CHUNK,GFP_ATOMIC);
        buf4=(char *) kmalloc(CHUNK,GFP_ATOMIC);    
	//printk("%p--%p\n", buf3, buf4);
    if(flag == 2)
    {
	//printk("Hello");
	if(fsize1 == fsize2)
        {
	     if(d_val == true)
		printk("I am in the n functionality\n");
	
	 	
        for(i=0; i<fsize1; i += min(CHUNK, fsize1-i))
        {
            bytes1 =  vfs_read(filp1, buf3, min(CHUNK, fsize1-i), &filp1->f_pos);
            bytes2 =  vfs_read(filp2, buf4, min(CHUNK, fsize1-i), &filp2->f_pos);

            for(j=0; j<min(CHUNK, fsize1-i); j++)
            {
		  if(buf3[j] == NULL || buf4[j] == NULL)
			goto exit;		

                  if(buf3[j] != buf4[j])
                  {
                    error = -1;
                    goto exit;
                  }
            }		
	    	
	    if(buf3 != NULL)
		kfree(buf3);
            if(buf4 != NULL)
		kfree(buf4);
        }
	
      }
     else
	{
		flag = 11;
	} 
    }

			
	if(buf3 != NULL)
                kfree(buf3);
        if(buf4 != NULL)
                kfree(buf4);
	


    if(flag == 4)
	{
	if(d_val == true)
		printk("Beginning of the working of Deduping functionality\n");
	
	  ret = 0;
	  if(fsize1 == fsize2)
	  {
		//printk("\n\nFile Size Checking\n");
		//printk("%d----->%d", fsize1, fsize2);
		for(i=0; i<fsize1; i += min(CHUNK, fsize1-i))
           	{
			
		//printk("In the for loop and value of ret is ---> %d\t", ret);
		bytes1 =  vfs_read(filp1, buf3, min(CHUNK, fsize1-i) , &filp1->f_pos);
                bytes2 =  vfs_read(filp2, buf4, min(CHUNK, fsize1-i), &filp2->f_pos);

            for(j=0; j<min(CHUNK, fsize1-i); j++)
            {

		if(buf3[j] == NULL || buf4[j] == NULL)
                 {	printk("Flag 4 in buf null\n");
			error = -1;
			goto exit;
		 }

                  if(buf3[j] != buf4[j])
                  {
			printk("Flag 4 two different chars  null\n");
                        error = -1;
                        goto exit;
                  }
                ret++;
            }
		printk("Return value %d\n", ret);
            if(buf3 != NULL)
                kfree(buf3);
            if(buf4 != NULL)
                kfree(buf4);		


		if(ret >= fsize1)
                {
			ret = fsize1;
                        if(buf3 != NULL)
                                kfree(buf3);
                        if(buf4 != NULL)
                                kfree(buf4);
			
			if(d_val == true)
				printk("The unlinking code is about to begin\n");
			//kern_path(pathname, LOOKUP_FOLLOW, &path);			
			
			kern_path(infile2, LOOKUP_FOLLOW, &path2);
			kern_path(infile1, LOOKUP_FOLLOW, &path1);
                	//lock
                	//mutex_lock();
                	mutex_lock(&path2.dentry->d_parent->d_inode->i_mutex);
			vfs_unlink(path2.dentry->d_parent->d_inode, path2.dentry, NULL);
			//unlock
			mutex_unlock(&path2.dentry->d_parent->d_inode->i_mutex);
			filename = filp2->f_path.dentry->d_iname; // filename: char*, newdentry: struct dentry newdentry
        	        //lock
        	        mutex_lock(&path2.dentry->d_parent->d_inode->i_mutex);
			newdentry = lookup_one_len(filp2->f_path.dentry->d_iname, path2.dentry->d_parent, strlen(filename));
			//unlock
			mutex_unlock(&path2.dentry->d_parent->d_inode->i_mutex);

			//printk("outside dentry\n");
                        if(newdentry == ERR_PTR(-ENOENT)){
               		         printk("inside if of dentry\n");
				return -8;
          	     	 }	
			//old : path1 // The file which is existing
			vfs_link(path1.dentry, path2.dentry->d_parent->d_inode, newdentry, NULL);
        
			
			if(d_val == true)
				printk("The unlinking is finished\n");
                        
			goto exit;
                }          
        }
      }
     else
	{
        	flag = 11;
	}
    }
   
    
		if(buf3 != NULL)
                	kfree(buf3);
                if(buf4 != NULL)
                	kfree(buf4);

    goto exit;

    exit:
	
	if(buf1 != NULL)
                 kfree(buf1);
        if(buf2 != NULL)
                 kfree(buf2);
	if(buf3 != NULL)
                 kfree(buf3);
        if(buf4 != NULL)
                 kfree(buf4);

	if(error != 0 || flag != 1)
	{
		
	if(buf1 != NULL)
                kfree(buf1);
            if(buf2 != NULL)
                kfree(buf2);
	if(buf3 != NULL)
                kfree(buf3);
            if(buf4 != NULL)
                kfree(buf4);
	set_fs(oldfs1);
	
        if(filp1 != NULL)
                filp_close(filp1, NULL);
        if(filp2 != NULL)
                filp_close(filp2, NULL);
        if(flag == 1)
                filp_close(filp3, NULL);
	
	}
    if(error == 0)
    {
        if(flag == 1)
        {
		// Execution is successful
		if(fileValid == true)
		{
			if(d_val == true)
			printk("I will begin unlinking the file present in the system and then rename the file\n");
			// Unlink the outfile1
			// Now, rename the file to outputfile
			filp4 = filp_open(outfile1, O_WRONLY, 0);
			kern_path(outfile1, LOOKUP_FOLLOW, &path3);
                        mutex_lock(&path3.dentry->d_parent->d_inode->i_mutex);
                        vfs_unlink(path3.dentry->d_parent->d_inode, path3.dentry, NULL);
                        mutex_unlock(&path3.dentry->d_parent->d_inode->i_mutex);
			
			
			//filename = filp2->f_path.dentry->d_iname;
			kern_path(outfile, LOOKUP_FOLLOW, &path1);
			//filp4 = filp_open(outfile1, O_WRONLY, 0);
			if(!filp4 || IS_ERR(filp4))
			{
				goto myend;
			}
			
			mutex_lock(&path1.dentry->d_parent->d_inode->i_mutex);
                        newdentry = lookup_one_len(filp4->f_path.dentry->d_iname, path1.dentry->d_parent, strlen(filp4->f_path.dentry->d_iname));
			mutex_unlock(&path1.dentry->d_parent->d_inode->i_mutex);
	
			vfs_rename(path1.dentry->d_parent->d_inode, path1.dentry, path3.dentry->d_parent->d_inode, newdentry , NULL, 0);
			if(d_val == true)
			printk("Renaming complete\n");
		}
	    
		if(buf1 != NULL)
                	kfree(buf1);
            	if(buf2 != NULL)
                	kfree(buf2);
        
	}
        else if(flag == 10)
            {
		//printk("Both the files are exactly same\n");
		return fsize1;
	    }
	else if(flag == 11)
	{
		//printk("The two files are not same\n");
		return -1;
	}
        else if(flag == 2)
	{
		//printk("I am on the flag 2 return\n");
            	return fsize1;
        }
	
	if(flag ==3 || d_val == true)
		printk("About to finish the operation \n");
	if(flag == 4)
		return ret;
	else
		return ret;

    }
    else
    {
	if(flag == 1)
	{
		if(d_val == true)
		printk("Handling when the renaming operation is not complete\n");
			kern_path(outfile, LOOKUP_FOLLOW, &path1);
			mutex_lock(&path1.dentry->d_parent->d_inode->i_mutex);
                        vfs_unlink(path1.dentry->d_parent->d_inode, path1.dentry, NULL);
			mutex_unlock(&path1.dentry->d_parent->d_inode->i_mutex);			
	}
	
	if(buf1 != NULL)
                kfree(buf1);
        if(buf2 != NULL)
                kfree(buf2);
	if(buf3 != NULL)
                kfree(buf3);
        if(buf4 != NULL)
                kfree(buf4);	

	if(filp1 != NULL)
                filp_close(filp1, NULL);
        if(filp2 != NULL)
                filp_close(filp2, NULL);
        if(filp3 != NULL)
                filp_close(filp3, NULL);
        if(filp4 != NULL)
                filp_close(filp4, NULL);
        if(flag == 1)
                filp_close(filp3, NULL);
	
	return error;
    }

	myend:
        if(buf1 != NULL)
                kfree(buf1);
        if(buf2 != NULL)
                kfree(buf2);
	if(buf3 != NULL)
                kfree(buf3);
        if(buf4 != NULL)
                kfree(buf4);

        if(filp1 != NULL)
                filp_close(filp1, NULL);
        if(filp2 != NULL)
                filp_close(filp2, NULL);
        if(filp3 != NULL)
                filp_close(filp3, NULL);
        if(filp4 != NULL)
                filp_close(filp4, NULL);
        set_fs(oldfs1);
                return ret;
	
	exit1:
	if(filp1 != NULL)
                filp_close(filp1, NULL);
        if(filp2 != NULL)
                filp_close(filp2, NULL);
        if(filp3 != NULL)
                filp_close(filp3, NULL);
        if(filp4 != NULL)
                filp_close(filp4, NULL);
	return error;
	
}


int xdedup(void *arg)
{
	struct xdedup_args *a;
	char **args;
	int args_count;
	int check;
	const char *infile1;
	const char *infile2;
	char *outfile;
        char tempFile[100];
	struct file *filp1;
    //char *buf1;
    int fsize1;
    //int i, j, k;
    struct file *filp2;
    //char *buf2;
    //int fsize2;
    //int ret;
    int err = 0;
    struct file *filp3 = NULL;
    struct kstat f1;
    struct kstat f2;
    struct kstat f3;
    int error1, error2;
    bool own = false;
    bool d_value = false;
    bool fileValid = false;
     
         struct timeval t;
	struct tm broken;
	do_gettimeofday(&t);
	time_to_tm(t.tv_sec, 0, &broken);
	//printk("%d:%d:%d:%ld\n", broken.tm_hour, broken.tm_min,broken.tm_sec, t.tv_usec);
	
	//strcat(tempFile, char(broken.tv_usec));
	sprintf(tempFile, "%d:%ld" , broken.tm_sec, t.tv_usec);
	//printk("Name is %s\n", tempFile);
	
	a = arg;
	args = a->param;
	args_count = a->count - a->index;

	if(a->b == 3 || a->b == 7)
	{
		a->b = 2;
		
		if(a->b == 7)
		    d_value = true;
	}	

	if (a->b == 1 || a->b == 5){
		//printk("I have entered the a->b = 1\n");
		if(a->b == 5)
		   d_value = true;			

		if (args_count < 3){
			printk("Missing arguments.\n");
			return -EINVAL;
		}
		else if (args_count > 3){
			printk("More than three file arguments passed.\n");
			return -EINVAL;
		}
		else {
			if(args[a->index] == NULL || args[a->index+1] == NULL ||  args[a->index+2] == NULL)
                        {
                                printk("One of the arguments passed is NULL");
                                return -EINVAL;
                        }			

			
		outfile = args[a->index+2];
		infile1 = args[a->index];
		infile2 = args[a->index+1];
		
                error1 = vfs_stat(infile1, &f1);
		error2 = vfs_stat(infile2, &f2);
	
    		filp1 = filp_open(infile1, O_RDONLY, 0);
    		if (!filp1 || IS_ERR(filp1)) {
        		printk("wrapfs_read_file err %d\n", (int) PTR_ERR(filp1));
        		err = -1;  // or do something else
			goto end;
   		 }

    		filp2 = filp_open(infile2, O_RDONLY, 0);
    		if (!filp2 || IS_ERR(filp2)) {
        		printk("wrapfs_read_file err %d\n", (int) PTR_ERR(filp2));
        		err =  -1;  // or do something else
			goto end;
   		 }
		
		error1 = vfs_stat(outfile, &f3);
		//printk("Value of Error1 ---%d\n", error1);
		
 		if(error1 < 0)
                 {
                        filp3 = filp_open(outfile, O_WRONLY | O_CREAT, 0664);
                        // printk("File doesn't exists\n");
                 }
                else
                {
                        //printk("File exists\n");
			filp3 = filp_open(outfile, O_WRONLY, 0664);
			if (!filp3 || IS_ERR(filp3)) {
                        	printk("wrapfs_read_file err %d\n", (int) PTR_ERR(filp3));
                        	err = -1;  // or do something else
                        	goto end;
                	 }
			//printk("New Temp File Generated\n");
                        filp3 = filp_open(tempFile, O_WRONLY | O_CREAT, 0);
                        fileValid = true;
                }	
		
    		//filp3 = filp_open(outfile, O_WRONLY | O_CREAT, 0);
        	if (!filp3 || IS_ERR(filp3)) {
        		printk("wrapfs_read_file err %d\n", (int) PTR_ERR(filp3));
        		err = -1;  // or do something else
			goto end;
   		 }
			
			//printk("Just above fileValid\n");	
			if(fileValid)
			{
			//printk("Hello\n");	
			check = wrapfs_read_file(tempFile, infile1, infile2,1, d_value, fileValid, outfile);
			}else
			check = wrapfs_read_file(outfile, infile1, infile2,1, d_value, fileValid, NULL);
			
			//printk("%d", check);

			end:
				if(filp1 != NULL)
                			filp_close(filp1, NULL);
        			if(filp2 != NULL)
                			filp_close(filp2, NULL);
        			if(filp3 != NULL)
                			filp_close(filp3, NULL);

				if(err == 0)
				     return check;
				else
				     return err;
		}
	}
	else{
		if (args_count < 2){
			printk("Missing arguments.\n");
			return -EINVAL;
		}
		else if (args_count > 2){
			printk("More than two file arguments passed.\n");
			return -EINVAL;
		}
		else{
			//printk("Received right arguments above flag n = 1.\n");
			if(a->b == 2 || a->b == 6)
			    {
				//printk("We are not doing dedup as per your request");
				
				if(a->b == 6)
				{
					d_value = true; 
				}

			//printk("Received right arguments for p.\n");
                        //printk("%s----%s\n", args[a->index], args[a->index+1]);
                        if(args[a->index] == NULL || args[a->index+1] == NULL) // ||  args[a->index+2] == NULL)
                        {
                                printk("One of the arguments passed is NULL");
                                return -EINVAL;
                        }

                infile1 = args[a->index];
                infile2 = args[a->index+1];

                filp1 = filp_open(infile1, O_RDONLY, 0);
                if (!filp1 || IS_ERR(filp1)) {
                        printk("wrapfs_read_file err %d\n", (int) PTR_ERR(filp1));
                        err = -1;  // or do something else
                        goto end1;
                 }

                filp2 = filp_open(infile2, O_RDONLY, 0);
                if (!filp2 || IS_ERR(filp2)) {
                        printk("wrapfs_read_file err %d\n", (int) PTR_ERR(filp2));
                        err =  -1;  // or do something else
                        goto end1;
                 }

		check = wrapfs_read_file(NULL, args[a->index], args[a->index+1], 2, d_value, fileValid, NULL);
		return check;

			end1:
                                if(filp1 != NULL)
                                        filp_close(filp1, NULL);
                                if(filp2 != NULL)
                                        filp_close(filp2, NULL);
                                if(filp3 != NULL)
                                        filp_close(filp3, NULL);

                                if(err == 0)
                                     return check;
                                else
                                     return err;
			    }

			else if(a->b == 4)
			    {
				
			//printk("Received right arguments for p.\n");
                        //printk("%s----%s\n", args[a->index], args[a->index+1]);
                        if(args[a->index] == NULL || args[a->index+1] == NULL) // ||  args[a->index+2] == NULL)
                        {
                                printk("One of the arguments passed is NULL");
                                return -EINVAL;
                        }

                infile1 = args[a->index];
                infile2 = args[a->index+1];

                filp1 = filp_open(infile1, O_RDONLY, 0);
                if (!filp1 || IS_ERR(filp1)) {
                        printk("wrapfs_read_file err %d\n", (int) PTR_ERR(filp1));
                        err = -1;  // or do something else
                        goto end2;
                 }

                filp2 = filp_open(infile2, O_RDONLY, 0);
                if (!filp2 || IS_ERR(filp2)) {
                        printk("wrapfs_read_file err %d\n", (int) PTR_ERR(filp2));
                        err =  -1;  // or do something else
                        goto end2;
                 }

			
			//printk("We will perform only dedup opertion");
                        check = wrapfs_read_file( NULL, args[a->index], args[a->index+1], 3, true, fileValid, NULL);
                        return check;

			end2:
                                if(filp1 != NULL)
                                        filp_close(filp1, NULL);
                                if(filp2 != NULL)
                                        filp_close(filp2, NULL);
                                if(filp3 != NULL)
                                        filp_close(filp3, NULL);

                                if(err == 0)
                                     return check;
                                else
                                     return err;
                            
			}
		 
		else if(a->b == 0)
		{
			
			//printk("Received right arguments for p.\n");
                        //printk("%s----%s\n", args[a->index], args[a->index+1]);
                        
		error1 = vfs_stat(infile1, &f1);
                error2 = vfs_stat(infile2, &f2);

                /*if(f1.uid.val != f2.uid.val)
                {
                        printk("The owner of the files is different\n");
			own = false;
			goto end3;
                } 
                else
                {
                        printk("The owner of the file is same\n");
			own = true;
			//goto end3;
                }*/

			if(args[a->index] == NULL || args[a->index+1] == NULL) // ||  args[a->index+2] == NULL)
                        {
                                printk("One of the arguments passed is NULL");
                                return -EINVAL;
                        }

                infile1 = args[a->index];
                infile2 = args[a->index+1];

                filp1 = filp_open(infile1, O_RDONLY, 0);
                if (!filp1 || IS_ERR(filp1)) {
                        printk("wrapfs_read_file err %d\n", (int) PTR_ERR(filp1));
                        err = -1;  // or do something else
                        return -1;
                 }

                filp2 = filp_open(infile2, O_RDONLY, 0);
                if (!filp2 || IS_ERR(filp2)) {
                        printk("wrapfs_read_file err %d\n", (int) PTR_ERR(filp2));
                        err =  -1;  // or do something else
                        return -1;
                 }

			if(own == false)
                        {
				//printk("We will perform only dedup opertion");
                                check = wrapfs_read_file( NULL, args[a->index], args[a->index+1], 4, true, fileValid, NULL);
                                return check;
			}

                        end3:
                                if(filp1 != NULL)
                                        filp_close(filp1, NULL);
                                if(filp2 != NULL)
                                        filp_close(filp2, NULL);
                                if(filp3 != NULL)
                                        filp_close(filp3, NULL);

                                if(err == 0)
                                     return check;
                                else
                                     return err;			
		} 
	    }
	  
	}
	/* dummy syscall: returns 0 for non null, -EINVAL for NULL */
	if (arg == NULL)
		return -EINVAL;
	else
		return 0;
    
}

static int __init init_sys_xdedup(void)
{
        //printk("installed new sys_xdedup module\n");
        if (sysptr == NULL)
                sysptr = xdedup;
        return 0;
}

static void  __exit exit_sys_xdedup(void)
{
        if (sysptr != NULL)
                sysptr = NULL;
       // printk("removed sys_xdedup module \n");
}
module_init(init_sys_xdedup);
module_exit(exit_sys_xdedup);
MODULE_LICENSE("GPL");


