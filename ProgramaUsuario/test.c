#include<stdio.h>
#include<stdlib.h>
#include<errno.h>
#include<fcntl.h>
#include<string.h>
#include<unistd.h>
 
#define BUFFER_LENGTH 256               ///< The buffer length (crude but fine)
static char receive[BUFFER_LENGTH];     ///< The receive buffer from the LKM
 
int main(){
	
	int opcao;
	int ret, fd;
  	char funcao[BUFFER_LENGTH];
	char stringToSend[BUFFER_LENGTH + 2];
	
	printf("Inicializando device teste...\n");
   	fd = open("/dev/cryptnum", O_RDWR);             // Abrir o device com leitura/escrita 
   	if (fd < 0){	      
	perror("Falha ao abrir o device...");
     	return errno;
  	}
	
	do{
	printf("Selecione sua opção\n");
	printf("1-Criptografia (c) \n 2-Descriptografia (d)\n 3-Hash (h)\n 4-Sair\n");	
	scanf("%d", &opcao);
	__fpurge(stdin);
  
   	printf("Digite sua mensagem para enviar ao kernel:\n");
   	scanf("%s", funcao);                // Pegando mensagem 
   

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
	
	default:
	return 0;
	break;
	}
   
	ret = write(fd, stringToSend, strlen(stringToSend)); // Envia string para o modulo do kernel 
	if (ret < 0){
     	perror("Falha para escrever a mensagem no device.");
    	return errno;
  	}
 

	ret = read(fd, receive, BUFFER_LENGTH);        // Lendo a resposta do Kernel
 	  if (ret < 0){
    	  perror("Falha ao ler a mensage do device.");
	  return errno;
  	 }
   	printf("%s\n", receive);

	}while(opcao != 4);

	printf("Finalilzando Programa\n");
   	return 0;
}
