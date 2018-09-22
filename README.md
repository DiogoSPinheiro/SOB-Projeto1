 SOB-Projeto1 - Driver criptográfico e descriptográfico
======

Este projeto tem como objetivo criar um dispositivo que criptografa e descriptografa dados inseridos pelo usuário, através de uma chave fornecida pelo mesmo.
A aplicação "trello" é para auxiliar na elaboração e desenvolvimento do projeto: https://trello.com/b/EmZKTnBN/projeto-1

Neste Projeto são utilizados dois programas:

Programa para carregar o driver (Espaço de Kernel).
------------
Este programa tem como objetivo carregar um driver responsável por criptograr (hash ou AES) e descriptograr dados baseado em uma chave fornecida, e armazenar o resultado da última operação. 

Programa para facilitar a comunicação de usuário com o driver (Espaço de Usuário).
------------
Este programa tem como objetivo facilitar a comunicação do usuário com o driver que faz a criptografia e descriptografia dos dados. Possui algumas funções como:
*c cifrar as informações.
*d decifrar as informações.
*h produzir o hash code em SHA.
*l leitura do resultado da última requisição.

Integrantes:
* Daniel Toloto: dctoloto@gmail.com
* Diogo Pinheiro: diogo.7.pinheiro@hotmail.com  
* Rodrigo Machado: rodrigomachado161@gmail.com


