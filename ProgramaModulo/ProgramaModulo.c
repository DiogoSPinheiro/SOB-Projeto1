#include <linux/init.h>           // Macros para utilizar com outros nomes __init __exit
#include <linux/module.h>         // Headers LKM
#include <linux/device.h>         // Header to support the kernel Driver Model
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/uaccess.h>          // FUncao de copiar para o usuario
#include <linux/mutex.h>
#include <linux/moduleparam.h>
#include <crypto/internal/hash.h>	//para o hash
#include <crypto/internal/skcipher.h>	//usado para o AES
#include <linux/crypto.h>	//usado para o AES

#define  DEVICE_NAME "cryptnum"    // /dev/cryptnum
#define  CLASS_NAME  "ebb"        // declarando classe de que eh um dispositivo de caractere
#define SHA256_LENGTH 32	// tamanho da mensagem


MODULE_LICENSE("GPL");            // Licensa
MODULE_AUTHOR("Daniel,Diogo,Rodrigo");    // Autores
MODULE_DESCRIPTION("Encriptador");  // modinfo
MODULE_VERSION("1.0");            // versao



static int    majorNumber;                  //< numero do dispositivo
static char   message[256] = {0};           //< memoria da string passada pelo usuario
static short  size_of_message;              //< lembrar tamanho da string passada
static struct class*  cryptnumClass  = NULL; //< ponteiro de struct device-driver
static struct device*  cryptnumDevice  = NULL; //< ponteiro de struct device-driver
static DEFINE_MUTEX(crypto_mutex);      //< mutex
static char *myKey = "00000000000000000000000000000000"; // criando a variavel para ler a chave inserida pelo usuario
module_param(myKey,charp, 0000);        //carregando a chave inserida

static struct skcipher_def sk;
static struct crypto_skcipher *skcipher = NULL;
static struct skcipher_request *req = NULL;
static char *scratchpad = NULL;
static unsigned char key[16];
char resposta[SHA256_LENGTH*2 + 1];

// Declaracao das funcoes do modulo

static int     dev_open(struct inode *, struct file *);
static int     dev_release(struct inode *, struct file *);
static ssize_t dev_read(struct file *, char *, size_t, loff_t *);
static ssize_t dev_write(struct file *, const char *, size_t, loff_t *);
static int encryptBuffer(char * bufferAux);
static int decryptBuffer(char * bufferAux);



/* todas as structs sob skcipher_def */
struct skcipher_def {
    struct scatterlist sg;
    struct crypto_skcipher *tfm;
    struct skcipher_request *req;
    struct crypto_wait wait;
};

// Definindo as funcoes do modulo

static struct file_operations fops =
{
    .open = dev_open,        // .open eh tratado como dev_open
    .read = dev_read,        // .read eh tratado como dev_read
    .write = dev_write,      // .write eh tratado como dev_write
    .release = dev_release,  // .release eh tratado como dev_release
};

// Mostrar hash //
static void show_hash_result(char * plaintext, char * hash_sha256)
{
    int i;
    char str[SHA256_LENGTH*2 + 1];

    pr_info("Hash: \"%s\"\n", plaintext);
    for (i = 0; i < SHA256_LENGTH ; i++){
        sprintf(&str[i*2],"%02hhx", (unsigned char)hash_sha256[i]);
	sprintf(&resposta[i*2],"%02hhx", (unsigned char)hash_sha256[i]);
	}
    str[i*2] = 0;
	resposta[i*2] = 0;
    pr_info("%s\n\n", str);
}

/* Hash no texto inserido pelo usuario*/

int cryptosha256(char * plaintext)
{
    char hash_sha256[SHA256_LENGTH];
    struct crypto_shash *sha256;
    struct shash_desc *shash;


    sha256 = crypto_alloc_shash("sha256", 0, 0);
    if (IS_ERR(sha256))
        return -1;

    shash =
        kmalloc(sizeof(struct shash_desc) + crypto_shash_descsize(sha256),
                GFP_KERNEL);
    if (!shash)
        return -ENOMEM;

    shash->tfm = sha256;
    shash->flags = 0;

    if (crypto_shash_init(shash))
        return -1;

    if (crypto_shash_update(shash, plaintext, strlen(plaintext)))
        return -1;

    if (crypto_shash_final(shash, hash_sha256))
        return -1;

    kfree(shash);
    crypto_free_shash(sha256);

/* Mostrar resultado do hash*/

    show_hash_result(plaintext, hash_sha256);

    return 0;
}



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

/* Initialize and trigger cipher operation */
static int test_skcipher(void)
{

    int ret = -EFAULT;
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

	/* Setando a chave*/

    if (crypto_skcipher_setkey(skcipher, key, 16)) { 
        pr_info("key could not be set\n");
        ret = -EAGAIN;
        goto out;
    }

    /* Alocar mensagem do usuario */
    scratchpad = kmalloc(16, GFP_KERNEL);
    if (!scratchpad) {
        pr_info("could not allocate scratchpad\n");
        goto out;
    }
	/* Inserir 16 bytes de dados da mensagem do usuario */
	

    sk.tfm = skcipher;
    sk.req = req;
    sg_init_one(&sk.sg, scratchpad, 16);

    skcipher_request_set_crypt(req, &sk.sg, &sk.sg, 16, 0);
    crypto_init_wait(&sk.wait);
	    		
out:
return 0;

}

static int encryptBuffer(char * bufferAux){
    /* We encrypt one block */
	int ret = -EFAULT;

  
	for(ret = 0; ret < 16; ret++){
	scratchpad[ret] = 0;
	}

	sprintf(scratchpad,"%s",bufferAux);
    	ret = test_skcipher_encdec(&sk, 1);

	for(ret = 0; ret<16; ret++){
	    pr_info("%02hhX",(unsigned char)scratchpad[ret]);
	}
	    pr_info("\n");


return ret;
}

static int decryptBuffer(char * bufferAux){
	int ret = -EFAULT;

	for(ret = 0; ret < 16; ret++){
	scratchpad[ret] = 0;
	}
	for(ret = 0; ret < 16; ret++){
	scratchpad[ret] = bufferAux[ret];
	}

    ret = test_skcipher_encdec(&sk, 0);

    sg_copy_from_buffer(&sk.sg, 1, scratchpad, 16);

	//scratchpad[strlen(scratchpad)+1] = '\0';
    	pr_info("%s",scratchpad);



return ret;
}
  
// *** Iniciando o modulo *** //


static int __init cryptnum_init(void){
	int i,j;
    
    printk(KERN_INFO "Inicializando cryptnum ...\n");
    
    // Tentativa de alocar dinamicamente o major number
    majorNumber = register_chrdev(0, DEVICE_NAME, &fops);
    if (majorNumber<0){
        printk(KERN_ALERT "Impossivel registrar em um major number\n");
        return majorNumber;
    }
    printk(KERN_INFO "Major number: %d\n", majorNumber);
    
    // Registrar na classe de dispositivo
    cryptnumClass = class_create(THIS_MODULE, CLASS_NAME);
    if (IS_ERR(cryptnumClass)){                // Checar por erro ou pelo cleanup
        unregister_chrdev(majorNumber, DEVICE_NAME);
        printk(KERN_ALERT "Falha ao registrar na classe de dispositivo\n");
        return PTR_ERR(cryptnumClass);          // Usar para debug
    }
    printk(KERN_INFO "Classe criada corretamente\n");
    
    // Registrar o driver do dispositivo
    cryptnumDevice = device_create(cryptnumClass, NULL, MKDEV(majorNumber, 0), NULL, DEVICE_NAME);
    if (IS_ERR(cryptnumDevice)){               // Se houver erros limpar
        unregister_chrdev(majorNumber, DEVICE_NAME);
        printk(KERN_ALERT "Falha ao criar o dispositivo\n");
        return PTR_ERR(cryptnumDevice);
    }
    printk(KERN_INFO "Dispositivo criado\n"); // Tudo certo para comecar, retorna 0
    mutex_init(&crypto_mutex); //semaforo iniciado   
	pr_info("\n");

     /* Chave convertida de char para HEX */

	j = 0;

	for(i=0;i < 16;i++){
		key[i]=0;		
	}

	if(strlen(myKey) < 32 ){

		for(i = 0; i < strlen(myKey)/2; i++){
			if(myKey[j] < 64 && myKey[j+1] < 64){
				key[i] = 16*(myKey[j]-48) + (myKey[j+1]-48);
			}
			else{
				if(myKey[j] > 64 && myKey[j+1] < 64){
				key[i] = 16*(myKey[j]-55) + (myKey[j+1]-48);
				}
				else{
					if(myKey[j] < 64 && myKey[j+1] > 64){
					key[i] = 16*(myKey[j]-48) + (myKey[j+1]-55);
					}
					else{
						key[i] = 16*(myKey[j]-64) + (myKey[j+1]-55);						
					}
				}
			}

		j+=2;
		}


		pr_info("A Chave inserida eh muito pequena por isso foram adicionados 0 ao seu final: "); //Chave com padding
		for(j = 0; j<16; j++){
	    		pr_info("%d %02hhX",j, (unsigned char)key[j]);
		}

	}else{

		for(i = 0; i<16;i++){
			if(myKey[j] < 64 && myKey[j+1] < 64){
				key[i] = 16*(myKey[j]-48) + (myKey[j+1]-48);
			}
			else{
				if(myKey[j] > 64 && myKey[j+1] < 64){
				key[i] = 16*(myKey[j]-55) + (myKey[j+1]-48);
				}
				else{
					if(myKey[j] < 64 && myKey[j+1] > 64){
					key[i] = 16*(myKey[j]-48) + (myKey[j+1]-55);
					}
					else{
						key[i] = 16*(myKey[j]-55) + (myKey[j+1]-55);						
					}
				}
			}
		j+=2;

		}

		printk("Chave inserida pelo usuario: "); // Confirmando a chave inserida pelo usuario	

		for(j = 0; j<16; j++){
	    		pr_info("%02hhX",(unsigned char)key[j]);
		}
		pr_info("\n");
}
	test_skcipher();
    
    return 0;
}

// *** Descarregando o modulo *** //

static void __exit cryptnum_exit(void){
    device_destroy(cryptnumClass, MKDEV(majorNumber, 0));     // remove o dispositivo
    class_unregister(cryptnumClass);                          // cancelar o registro da classe do dispositivo
    class_destroy(cryptnumClass);                             // remove a classe do dispositivo
    unregister_chrdev(majorNumber, DEVICE_NAME);             // cancelar o registro do major number
    crypto_free_skcipher(skcipher);
    skcipher_request_free(req);
    kfree(scratchpad);
    mutex_destroy(&crypto_mutex);               // mutex eh destruido
    printk(KERN_INFO "Dispositivo descarregado\n");
}

// *** Abrindo o modulo *** //

static int dev_open(struct inode *inodep, struct file *filep){
    
    if(!mutex_trylock(&crypto_mutex)){    // tenta localizar o mutex e travar
        /// resulta 1 em sucesso ou erro caso nao
        printk(KERN_ALERT "Dispositivo esta em utilizacao por outro processo");
        return -EBUSY;
    }
    
    return 0;
}

// *** Lendo o modulo *** //

static ssize_t dev_read(struct file *filep, char *buffer, size_t len, loff_t *offset){
    int error_count = 0;         // incializado com 0
    
    error_count = copy_to_user(buffer, resposta,SHA256_LENGTH*2 + 1 );    // copy_to_user(para,de,tamanho) retorna 0 se sucesso
    
    if (error_count==0){            // caso sucesso a mensagem eh enviada

        return (size_of_message=0);  // limpa posicao e retorna 0
    }
    else {
        printk(KERN_INFO "Falha impossivel mandar %d caracteres para o usuario\n", error_count);
        return -EFAULT;              // erro retorna um endereco errado.
    }
}

// *** Escrevendo no modulo *** //

static ssize_t dev_write(struct file *filep, const char *buffer, size_t len, loff_t *offset){
    

	char buf[16];
	int i = strlen(buffer) - 2;
	int j,m,n;
		
    switch (buffer[0]){
            
        case 'c':
            sprintf(message, "Criptografia");
		m = 0;
	do{
		for(j =0;j < 16;j++){
		buf[j] = 0;
		}
		if(i>=16){
			for(j =0;j < 16;j++){
			buf[j] = buffer[j+2+(strlen(buffer)-2 -i)];
			}
		}else{
			for(j =0;j < i;j++){
			buf[j] = buffer[j+2+(strlen(buffer)-2 -i)];
			}

		}
		encryptBuffer(buf);

		j =0;
   		 for (n = m*16; n < (m*16)+16 ; n++){
			sprintf(&resposta[(n*2)],"%02hhx", (unsigned char)scratchpad[j]);
			j++;
		}
		resposta[n*2] = 0;

		i -= 16;
		m++;
	}while(i > 0);
	
            break;
            
        case 'd':

	i = strlen(buffer)/32;

	for(n=0;n<i;n++){		
		for(j =0;j < 16;j++){
		buf[j] = 0;
		}

		j=(n*32)+2; 
		for(m = 0; m<16;m++){
			if(buffer[j] < 64 && buffer[j+1] < 64){
				buf[m] = 16*(buffer[j]-48) + (buffer[j+1]-48);
			}
			else{
				if(buffer[j] > 64 && buffer[j+1] < 64){
				buf[m] = 16*(buffer[j]-55) + (buffer[j+1]-48);
				}
				else{
					if(buffer[j] < 64 && buffer[j+1] > 64){
					buf[m] = 16*(buffer[j]-48) + (buffer[j+1]-55);
					}
					else{
						buf[m] = 16*(buffer[j]-55) + (buffer[j+1]-55);					
					}
				}
			}
		j+=2;

		}

			decryptBuffer(buf);
			sprintf(&(resposta[n*16]),"%s",scratchpad);

	} // fim  do for
			resposta[16*n] = 0;
			for(i = 0; i<16; i++){
	    		pr_info("%02hhX",(unsigned char)buf[i]); // 5DE9495B5F5D2688E4804530B267035F
			//C4DD4777A69F49F8D070073D9B0164DB
			//C4DD4777A69F49F8D070073D9B0164DBAB64D22072D8A7255D5746F189BD83E9
			//C4DD4777A69F49F8D070073D9B0164DBC4DD4777A69F49F8D070073D9B0164DBAB64D22072D8A7255D5746F189BD83E9
		}	


            break;
            
        case 'h':
            sprintf(message, "Hash");
		sprintf(buf,"%s",&(buffer[2]));
		cryptosha256(buf);
            break;
            
        default:
            sprintf(message,"Error");
            break;
            
    }
    
return 0;
}

// *** Liberando dispositivo *** //

static int dev_release(struct inode *inodep, struct file *filep){
    printk(KERN_INFO "Dispositivo finalizado\n\n\n");
    mutex_unlock(&crypto_mutex);       //mutex eh liberado
    return 0;
}

module_init(cryptnum_init);
module_exit(cryptnum_exit);
