#include <stdio.h>      /* printf, sprintf */
#include <stdlib.h>     /* exit, atoi, malloc, free */
#include <unistd.h>     /* read, write, close */
#include <string.h>     /* memcpy, memset */
#include <sys/socket.h> /* socket, connect */
#include <netinet/in.h> /* struct sockaddr_in, struct sockaddr */
#include <netdb.h>      /* struct hostent, gethostbyname */
#include <arpa/inet.h>

#include "helpers.h"
#include "requests.h"
#include "parson.h"

#define MAX_LEN 100

#define HOST "34.241.4.235"
#define PORT 8080

/* verifica username sau parola (nu pot contine spatii)
1 - sir valid, 0 - altfel */
int validate(char* str) {
    if (strcmp(str, "\n") == 0) { // sir gol
        return 0;
    }

    if (strstr(str, " ")) { // contine spatii
        return 0;
    }

    return 1;
}

/* verifica daca sirul contine numai cifre (este un numar natural)
1 - numar valid, 0 - altfel */
int valid_number(char* str) {
    for (int i = 0; i < strlen(str); i++) {
        if (!(str[i] >= '0' && str[i] <= '9')) {
            return 0;
        }
    }

    return 1;
}

/* verifica daca sirul este gol / contine doar spatii
1 - sir vid, 0 - altfel */
int is_empty(char* str) {
    if (strcmp(str, "\n") == 0) {
        return 1;
    }

    for (int i = 0; i < strlen(str); i++) {
        if (str[i] != ' ') {
            return 0;
        }
    }
    
    return 1;
}

int main(int argc, char* argv[])
{
    int sockfd;

    char* message;
    char* response;
    char* buffer;

    char* cookie = NULL;
    char* token = NULL;

    while (1) {

        char* command = malloc(MAX_LEN * sizeof(char));

        fgets(command, MAX_LEN, stdin);
        strtok(command, "\n");

        if (strcmp(command, "exit") == 0) {
            free(command);
            break;
        }

        sockfd = open_connection(HOST, PORT, AF_INET, SOCK_STREAM, 0);

        if (strcmp(command, "register") == 0) {

            JSON_Value* root_value = json_value_init_object();
            JSON_Object* root_object = json_value_get_object(root_value);
            char* serialized_string = NULL;

            while (1) {
                printf("username=");
                buffer = malloc(MAX_LEN * sizeof(char));
                fgets(buffer, MAX_LEN, stdin);
                strtok(buffer, "\n");
                if (validate(buffer)) {
                    break;
                } else {
                    printf("Wrong format! Username can't be empty or contain spaces.\n");
                    free(buffer);
                }
            }
            json_object_set_string(root_object, "username", buffer);
            free(buffer);

            while (1) {
                printf("password=");
                buffer = malloc(MAX_LEN * sizeof(char));
                fgets(buffer, MAX_LEN, stdin);
                strtok(buffer, "\n");
                if (validate(buffer)) {
                    break;
                } else {
                    printf("Wrong format! Password can't be empty or contain spaces.\n");
                    free(buffer);
                }
            }
            json_object_set_string(root_object, "password", buffer);
            free(buffer);

            serialized_string = json_serialize_to_string_pretty(root_value);

            message = compute_post_request(HOST, "/api/v1/tema/auth/register", 
                    "application/json", &serialized_string, 1, NULL, 0, NULL);
            send_to_server(sockfd, message);
            response = receive_from_server(sockfd);

            if (strstr(response, "Bad Request") && strstr(response, "is taken")) {
                printf("Error: username is already taken!\n");
            } else if (strstr(response, "Created")) {
                printf("Success: account registered successfully!\n");
            }

            json_free_serialized_string(serialized_string);
            json_value_free(root_value);
        }

        if (strcmp(command, "login") == 0) {

            if (cookie != NULL) {
                printf("Error: already logged in!\n");
            } else {
                JSON_Value* root_value = json_value_init_object();
                JSON_Object* root_object = json_value_get_object(root_value);
                char* serialized_string = NULL;

                while (1) {
                    printf("username=");
                    buffer = malloc(MAX_LEN * sizeof(char));
                    fgets(buffer, MAX_LEN, stdin);
                    strtok(buffer, "\n");
                    if (validate(buffer)) {
                        break;
                    } else {
                        printf("Wrong format! Username can't be empty or contain spaces.\n");
                        free(buffer);
                    }
                }
                json_object_set_string(root_object, "username", buffer);
                free(buffer);

                while (1) {
                    printf("password=");
                    buffer = malloc(MAX_LEN * sizeof(char));
                    fgets(buffer, MAX_LEN, stdin);
                    strtok(buffer, "\n");
                    if (validate(buffer)) {
                        break;
                    } else {
                        printf("Wrong format! Password can't be empty or contain spaces.\n");
                        free(buffer);
                    }
                }
                json_object_set_string(root_object, "password", buffer);
                free(buffer);

                serialized_string = json_serialize_to_string_pretty(root_value);

                message = compute_post_request(HOST, "/api/v1/tema/auth/login", 
                        "application/json", &serialized_string, 1, NULL, 0, NULL);
                send_to_server(sockfd, message);
                response = receive_from_server(sockfd);

                if (strstr(response, "Bad Request")) {
                    if (strstr(response, "No account with this username")) {
                        printf("Error: an account with this username doesn't exist!\n");
                    }
                    if (strstr(response, "Credentials are not good")) {
                        printf("Error: credentials do not match!\n");
                    }
                } else if (strstr(response, "OK")) {
                    printf("Success: logged in successfully!\n");
                    cookie = strstr(response, "Set-Cookie: ") + strlen("Set-Cookie: ");
                    strtok(cookie, ";");
                    printf("Session cookie: %s\n", cookie);
                }

                json_free_serialized_string(serialized_string);
                json_value_free(root_value);
            }
        }

        if (strcmp(command, "enter_library") == 0) {

            if (cookie == NULL) {
                printf("Error: you are not logged in!\n");
            } else {
                message = compute_get_request(HOST, "/api/v1/tema/library/access", 
                        NULL, &cookie, 1, NULL);
                send_to_server(sockfd, message);
                response = receive_from_server(sockfd);

                if (strstr(response, "OK")) {
                    printf("Success: successfully obtained access to the library!\n");
                    token = strstr(response, "\"token\":\"") + strlen("\"token\":\"");
                    strtok(token, "\"");
                    printf("Token: %s\n", token);
                } else {
                    printf("Error: couldn't obtain access to the library!\n");
                }

            }
        }

        if (strcmp(command, "get_books") == 0) {
            
            if (token == NULL) {
                printf("Error: you don't have access to the library!\n");
            } else {
                message = compute_get_request(HOST, "/api/v1/tema/library/books", 
                        NULL, &cookie, 1, token);
                send_to_server(sockfd, message);
                response = receive_from_server(sockfd);

                if (strstr(response, "OK")) {
                    printf("Success: list of books:\n");
                    char* books = strstr(response, "[");
                    JSON_Value* root_value = json_parse_string(books);
                    char* serialized_string = json_serialize_to_string_pretty(root_value);
                    printf("%s\n", serialized_string);

                    json_free_serialized_string(serialized_string);
                    json_value_free(root_value);
                } else {
                    printf("Error: couldn't get list of books!\n");
                }

            }
        }

        if (strcmp(command, "get_book") == 0) {

            if (token == NULL) {
                printf("Error: you don't have access to the library!\n");
            } else {

                while (1) {
                    printf("id=");
                    buffer = malloc(MAX_LEN * sizeof(char));
                    fgets(buffer, MAX_LEN, stdin);
                    strtok(buffer, "\n");
                    if (valid_number(buffer)) {
                        break;
                    } else {
                        printf("Wrong format! ID must be a number!\n");
                        free(buffer);
                    }
                }

                char* book_route = 
                    malloc(strlen("/api/v1/tema/library/books/") + strlen(buffer) + 1);

                strcpy(book_route, "/api/v1/tema/library/books/");
                strcat(book_route, buffer);

                message = compute_get_request(HOST, book_route, NULL, &cookie, 1, token);
                send_to_server(sockfd, message);
                response = receive_from_server(sockfd);

                if (strstr(response, "Not Found")) {
                    printf("Error: book with given ID doesn't exist!\n");
                } else if (strstr(response, "OK")) {
                    printf("Success: book:\n");
                    char* book = strstr(response, "{");
                    strtok(book, "]");
                    JSON_Value* root_value = json_parse_string(book);
                    char* serialized_string = json_serialize_to_string_pretty(root_value);
                    printf("%s\n", serialized_string);

                    json_free_serialized_string(serialized_string);
                    json_value_free(root_value);
                }

                free(buffer);
                free(book_route);
            }
        }

        if (strcmp(command, "add_book") == 0) {

         if (token == NULL) {
                printf("Error: you don't have access to the library!\n");
            } else {
                JSON_Value* root_value = json_value_init_object();
                JSON_Object* root_object = json_value_get_object(root_value);
                char* serialized_string = NULL;

                while (1) {
                    printf("title=");
                    buffer = malloc(MAX_LEN * sizeof(char));
                    fgets(buffer, MAX_LEN, stdin);
                    strtok(buffer, "\n");
                    if (!is_empty(buffer)) { // sir nevid
                        break;
                    } else {
                        printf("Wrong format! Title can't be empty!\n");
                        free(buffer);
                    }
                }
                json_object_set_string(root_object, "title", buffer);
                free(buffer);

                while (1) {
                    printf("author=");
                    buffer = malloc(MAX_LEN * sizeof(char));
                    fgets(buffer, MAX_LEN, stdin);
                    strtok(buffer, "\n");
                    if (!is_empty(buffer)) { // sir nevid
                        break;
                    } else {
                        printf("Wrong format! Author can't be empty!\n");
                        free(buffer);
                    }
                }
                json_object_set_string(root_object, "author", buffer);
                free(buffer);

                while (1) {
                    printf("genre=");
                    buffer = malloc(MAX_LEN * sizeof(char));
                    fgets(buffer, MAX_LEN, stdin);
                    strtok(buffer, "\n");
                    if (!is_empty(buffer)) { // sir nevid
                        break;
                    } else {
                        printf("Wrong format! Genre can't be empty!\n");
                        free(buffer);
                    }
                }
                json_object_set_string(root_object, "genre", buffer);
                free(buffer);

                while (1) {
                    printf("publisher=");
                    buffer = malloc(MAX_LEN * sizeof(char));
                    fgets(buffer, MAX_LEN, stdin);
                    strtok(buffer, "\n");
                    if (!is_empty(buffer)) { // sir nevid
                        break;
                    } else {
                        printf("Wrong format! Publisher can't be empty!\n");
                        free(buffer);
                    }
                }
                json_object_set_string(root_object, "publisher", buffer);
                free(buffer);

                while (1) {
                    printf("page_count=");
                    buffer = malloc(MAX_LEN * sizeof(char));
                    fgets(buffer, MAX_LEN, stdin);
                    strtok(buffer, "\n");
                    if (valid_number(buffer)) {
                        break;
                    } else {
                        printf("Wrong format! page_count must be a number!\n");
                        free(buffer);
                    }
                }
                json_object_set_string(root_object, "page_count", buffer);
                free(buffer);

                serialized_string = json_serialize_to_string_pretty(root_value);

                message = compute_post_request(HOST, "/api/v1/tema/library/books", 
                        "application/json", &serialized_string, 1, &cookie, 1, token);
                send_to_server(sockfd, message);
                response = receive_from_server(sockfd);

                if (strstr(response, "OK")) {
                    printf("Success: book was added!\n");
                }

                json_free_serialized_string(serialized_string);
                json_value_free(root_value);
            }
        }

        if (strcmp(command, "delete_book") == 0) {
            
            if (token == NULL) {
                printf("Error: you don't have access to the library!\n");
            } else {

                while (1) {
                    printf("id=");
                    buffer = malloc(MAX_LEN * sizeof(char));
                    fgets(buffer, MAX_LEN, stdin);
                    strtok(buffer, "\n");
                    if (valid_number(buffer)) {
                        break;
                    } else {
                        printf("Wrong format! ID must be a number!\n");
                        free(buffer);
                    }
                }

                char* book_route = 
                    malloc(strlen("/api/v1/tema/library/books/") + strlen(buffer) + 1);

                strcpy(book_route, "/api/v1/tema/library/books/");
                strcat(book_route, buffer);

                message = compute_delete_request(HOST, book_route, NULL, &cookie, 1, token);
                send_to_server(sockfd, message);
                response = receive_from_server(sockfd);

                if (strstr(response, "Not Found")) {
                    printf("Error: book with given ID doesn't exist!\n");
                } else if (strstr(response, "OK")) {
                    printf("Success: book was deleted!\n");
                }

                free(buffer);
                free(book_route);
            }
        }

        if (strcmp(command, "logout") == 0) {

            if (cookie == NULL) {
                printf("Error: you are not logged in!\n");
            } else {
                message = compute_get_request(HOST, "/api/v1/tema/auth/logout", 
                        NULL, &cookie, 1, token);
                send_to_server(sockfd, message);
                response = receive_from_server(sockfd);

                if (strstr(response, "OK")) {
                    printf("Success: logged out successfully!\n");
                    cookie = NULL;
                    token = NULL;
                }

            }
        }

        close_connection(sockfd);

        free(command);
    }

    return 0;
}
