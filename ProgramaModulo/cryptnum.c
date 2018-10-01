#include <linux/init.h>           // Macros para utilizar com outros nomes __init __exit
#include <linux/module.h>         // Headers LKM
#include <linux/device.h>         // Header to support the kernel Driver Model
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/uaccess.h>          // FUncao de copiar para o usuario
#include <linux/mutex.h>
#include <linux/moduleparam.h>
#include <crypto/internal/hash.h>	//para o hash

#define  DEVICE_NAME "cryptnum"    // /proc/cryptnum
#define  CLASS_NAME  "ebb"        // declarando classe de que eh um dispositivo de caractere
#define SHA256_LENGTH 32	// tamanho da mensagem


MODULE_LICENSE("GPL");            // Licensa
MODULE_AUTHOR("Daniel,Diogo,Rodrigo");    // Autores
MODULE_DESCRIPTION("Encriptador");  // modinfo
MODULE_VERSION("0.1");            // versao

static int    majorNumber;                  //< numero do dispositivo
static char   message[256] = {0};           //< memoria da string passada pelo usuario
static short  size_of_message;              //< lembrar tamanho da string passada
static int    numberOpens = 0;              //< numero de vezes que o dispositivo foi aberto
static struct class*  cryptnumClass  = NULL; //< ponteiro de struct device-driver
static struct device*  cryptnumDevice  = NULL; //< ponteiro de struct device-driver
static DEFINE_MUTEX(crypto_mutex);      //< mutex
static char *myKey = "0";           // criando a variavel para ler a chave inserida pelo usuario
module_param(myKey,charp, 0000);        //carregando a chave inserida


// Declaracao das funcoes do modulo

static int     dev_open(struct inode *, struct file *);
static int     dev_release(struct inode *, struct file *);
static ssize_t dev_read(struct file *, char *, size_t, loff_t *);
static ssize_t dev_write(struct file *, const char *, size_t, loff_t *);

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

    pr_info("sha256 test for string: \"%s\"\n", plaintext);
    for (i = 0; i < SHA256_LENGTH ; i++)
        sprintf(&str[i*2],"%02x", (unsigned char)hash_sha256[i]);
    str[i*2] = 0;
    pr_info("%s\n", str);
}

int cryptosha256(void)
{
    char * plaintext = myKey;
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

    show_hash_result(plaintext, hash_sha256);

    return 0;
}




// *** Iniciando o modulo *** //


static int __init cryptnum_init(void){
    
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
        class_destroy(cryptnumClass);           // codigo repetido mas usa um goto para os estados
        unregister_chrdev(majorNumber, DEVICE_NAME);
        printk(KERN_ALERT "Falha ao criar o dispositivo\n");
        return PTR_ERR(cryptnumDevice);
    }
    printk(KERN_INFO "Dispositivo criado\n"); // Tudo certo para comecar, retorna 0
    mutex_init(&crypto_mutex); //semaforo iniciado
    
    printk("Chave inserida pelo usuario %s\n",myKey); // Confirmando a chave inserida pelo usuario
    
    
    return 0;
}

// *** Descarregando o modulo *** //

static void __exit cryptnum_exit(void){
    device_destroy(cryptnumClass, MKDEV(majorNumber, 0));     // remove o dispositivo
    class_unregister(cryptnumClass);                          // cancelar o registro da classe do dispositivo
    class_destroy(cryptnumClass);                             // remove a classe do dispositivo
    unregister_chrdev(majorNumber, DEVICE_NAME);             // cancelar o registro do major number
    printk(KERN_INFO "Dispositivo descarregado\n");
    mutex_destroy(&crypto_mutex);               // mutex eh destruido
}

// *** Abrindo o modulo *** //

static int dev_open(struct inode *inodep, struct file *filep){
    
    if(!mutex_trylock(&crypto_mutex)){    // tenta localizar o mutex e travar
        /// resulta 1 em sucesso ou erro caso nao
        printk(KERN_ALERT "Dispositivo esta em utilizacao por outro processo");
        return -EBUSY;
    }
    
    numberOpens++;
    printk(KERN_INFO "Dispositivo aberto %d vezes\n", numberOpens);
    return 0;
}

// *** Lendo o modulo *** //

static ssize_t dev_read(struct file *filep, char *buffer, size_t len, loff_t *offset){
    int error_count = 0;         // incializado com 0
    
    error_count = copy_to_user(buffer, message, size_of_message);    // copy_to_user(para,de,tamanho) retorna 0 se sucesso
    
    if (error_count==0){            // caso sucesso a mensagem eh enviada
        printk(KERN_INFO "%d caracteres foram enviados para o usuario\n", size_of_message);
        return (size_of_message=0);  // limpa posicao e retorna 0
    }
    else {
        printk(KERN_INFO "Falha impossivel mandar %d caracteres para o usuario\n", error_count);
        return -EFAULT;              // erro retorna um endereco errado.
    }
}

// *** Escrevendo no modulo *** //

static ssize_t dev_write(struct file *filep, const char *buffer, size_t len, loff_t *offset){
    
    
    
    switch (buffer[0]){
            
        case 'c':
            sprintf(message, "Criptografia");
		cryptosha256();
            break;
            
        case 'd':
            sprintf(message, "Descriptografia");
            break;
            
        case 'h':
            sprintf(message, "Hash");
            break;
            
        default:
            sprintf(message,"Error");
            break;
            
    }
    size_of_message = strlen(message);                 // capturando o tamanho da mensagem
    
    printk(KERN_INFO "Recebidos %zu caracteres do usuario\n", len);
    return len;
}

// *** Liberando dispositivo *** //

static int dev_release(struct inode *inodep, struct file *filep){
    printk(KERN_INFO "Dispositivo finalizado\n");
    mutex_unlock(&crypto_mutex);       //mutex eh liberado
    return 0;
}

module_init(cryptnum_init);
module_exit(cryptnum_exit);
