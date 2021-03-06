#include <crypto/internal/skcipher.h>
#include <linux/module.h>
#include <linux/crypto.h>

/* tie all data structures together */
struct skcipher_def {
    struct scatterlist sg;
    struct crypto_skcipher *tfm;
    struct skcipher_request *req;
    struct crypto_wait wait;
};

/* Perform cipher operation */
static unsigned int test_skcipher_encdec(struct skcipher_def *sk,int enc)
{
    int rc;

    if (enc!=0)
        rc = crypto_wait_req(crypto_skcipher_encrypt(sk->req), &sk->wait);
    else
        rc = crypto_wait_req(crypto_skcipher_decrypt(sk->req), &sk->wait);

    if (rc)
            pr_info("skcipher encrypt returned with result %d\n", rc);

    return rc;
}

static struct file_operations fops =
{
    .open = dev_open,        // .open eh tratado como dev_open
    .read = dev_read,        // .read eh tratado como dev_read
    .write = dev_write,      // .write eh tratado como dev_write
    .release = dev_release,  // .release eh tratado como dev_release
};

static int     dev_open(struct inode *, struct file *);
static int     dev_release(struct inode *, struct file *);
static ssize_t dev_read(struct file *, char *, size_t, loff_t *);
static ssize_t dev_write(struct file *, const char *, size_t, loff_t *);

/* Initialize and trigger cipher operation */
static int test_skcipher(void)
{
    struct skcipher_def sk;
    struct crypto_skcipher *skcipher = NULL;
    struct skcipher_request *req = NULL;
    char *scratchpad = NULL;
    char *ivdata = NULL;
    unsigned char key[32];
    int ret = -EFAULT;
	int i,j;
	unsigned char key2[16];

    skcipher = crypto_alloc_skcipher("ecb-aes-aesni", 0, 0);
    if (IS_ERR(skcipher)) {
        pr_info("could not allocate skcipher handle\n");
        return PTR_ERR(skcipher);
    }

    req = skcipher_request_alloc(skcipher, GFP_KERNEL);
    if (!req) {
        pr_info("could not allocate skcipher request\n");
        ret = -ENOMEM;
        goto out;
    }

    /* AES 256 with random key */

	sprintf(key,"password123"); 

    if (crypto_skcipher_setkey(skcipher, key, 16)) { //**
        pr_info("key could not be set\n");
        ret = -EAGAIN;
        goto out;
    }

    /* Input data will be random */
    scratchpad = kmalloc(16, GFP_KERNEL);
    if (!scratchpad) {
        pr_info("could not allocate scratchpad\n");
        goto out;
    }

	sprintf(scratchpad,"Testing");

    sk.tfm = skcipher;
    sk.req = req;

    /* We encrypt one block */
    sg_init_one(&sk.sg, scratchpad, 16);

    skcipher_request_set_crypt(req, &sk.sg, &sk.sg, 16, 0);
    crypto_init_wait(&sk.wait);
	i = sizeof(scratchpad);
	do{
    /* encrypt data */
    ret = test_skcipher_encdec(&sk, 1);

	for(j = 0; j<16; j++){
	    pr_info("%02X",(char unsigned) scratchpad[j]);
	}
	i = i - sizeof(scratchpad);
}while(i > 16);

	i = sizeof(scratchpad);

	do{
    ret = test_skcipher_encdec(&sk, 0);

    sg_copy_from_buffer(&sk.sg, 1, scratchpad, 16);
    pr_info("%s\n\n",scratchpad);
}while(i > 16);


    if (ret)
        goto out;




out:
    if (skcipher)
        crypto_free_skcipher(skcipher);
    if (req)
        skcipher_request_free(req);
    if (ivdata)
        kfree(ivdata);
    if (scratchpad)
        kfree(scratchpad);
    return ret;
}

int cryptoapi_init(void)
{
   test_skcipher();
    return 0;
}

void cryptoapi_exit(void)
{

}

module_init(cryptoapi_init);
module_exit(cryptoapi_exit);

MODULE_AUTHOR("Bob Mottram");
MODULE_DESCRIPTION("Symmetric key encryption example");
MODULE_LICENSE("GPL");

