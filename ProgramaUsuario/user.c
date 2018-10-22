#include<stdio.h>
#include<stdlib.h>
#include<errno.h>
#include<fcntl.h>
#include<string.h>
#include<unistd.h>
 
#define BUFFER_LENGTH 256               ///< The buffer length (crude but fine)
static char receive[BUFFER_LENGTH];     ///< The receive buffer from the LKM
int __fpurge(FILE *stream);

int main(){
	
	int opcao;
	int ret, fd;
  	char funcao[BUFFER_LENGTH];
	char stringToSend[BUFFER_LENGTH + 2];
	char out;
	
	printf("Inicializando device teste cryptnum...\n");
   	fd = open("/dev/cryptnum", O_RDWR);             // Abrir o device com leitura/escrita 
   	if (fd < 0){	      
	perror("Falha ao abrir o device...");
     	return errno;
  	}
	do{	
		system("clear");	
		printf("\t\t********************************************\n");
		printf("\t\t** Projeto 1 SOB - criptografia em modulo **\n");
		printf("\t\t********************************************\n");
		printf("\t\t\t\t    MENU\n\n\n");
		printf("\t\t\t    1-Criptografia (c)\n");
		printf("\t\t\t    2-Descriptografia (d)\n");
		printf("\t\t\t    3-Hash (h)\n");
		printf("\t\t\t    4--Sair\n\n\n");
		printf("\t\t********************************************\n");
	__fpurge(stdin);
	scanf("%d", &opcao);
	printf("\n");
  
	if(opcao <4 && opcao > 0){
   	printf("Digite sua mensagem para enviar ao kernel:\n");
   	scanf("%s", funcao);                // Pegando mensagem 
   	}

	switch (opcao) {
	case 1: 
		strcpy(stringToSend, "c ");
		strcat(stringToSend,funcao);
	break;
	
	case 2: 
		strcpy(stringToSend, "d ");
		strcat(stringToSend,funcao);
	break; 

	case 3:
		strcpy(stringToSend, "h ");
		strcat(stringToSend,funcao);
	break;
	
	case 4: printf("Finalizando o programa\n");
		return 0;
		break;
	
	default:
		printf("Comando invalido, finalizando programa\n");
		return 0;
	break;
	}

	ret = write(fd, stringToSend, strlen(stringToSend)); // Envia string para o modulo do kernel 
	if (ret < 0){
     	perror("Falha para escrever a mensagem no device.");
    	return errno;
  	} 
	__fpurge(stdin);
	ret = read(fd, receive, BUFFER_LENGTH);        // Lendo a resposta do Kernel
	__fpurge(stdin);
 	  if (ret < 0){
    	  perror("Falha ao ler a mensagem do device.");
	  return errno;
	}

	//if(opcao != 1){
	printf("\nResposta: %s\n", receive);
	/*}else{
		for(ret = 0; ret<16; ret++){
	    		printf("%02hhX",(unsigned char)receive[ret]);
		}
	}*/

	printf("\nPressiona alguma tecla\n");
	__fpurge(stdin);
	scanf("%c",&out);

	}while(opcao < 4 && opcao > 0);
   	return 0;
}
