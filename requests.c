#include <stdlib.h>     /* exit, atoi, malloc, free */
#include <stdio.h>
#include <unistd.h>     /* read, write, close */
#include <string.h>     /* memcpy, memset */
#include <sys/socket.h> /* socket, connect */
#include <netinet/in.h> /* struct sockaddr_in, struct sockaddr */
#include <netdb.h>      /* struct hostent, gethostbyname */
#include <arpa/inet.h>

#include "helpers.h"
#include "requests.h"

char *compute_post_request(char* host, char* url, char* content_type, 
						char** body_data, int body_data_fields_count, 
						char** cookies, int cookies_count, char* token) {
	char* message = calloc(BUFLEN, sizeof(char));
	char* line = calloc(LINELEN, sizeof(char));
	char* body_data_buffer = calloc(LINELEN, sizeof(char));

	sprintf(line, "POST %s HTTP/1.1", url);
	compute_message(message, line);
	
	memset(line, 0, LINELEN);
	sprintf(line, "Host: %s", host);
	compute_message(message, line);

	int body_data_size = 0;
	for (int i = 0; i < body_data_fields_count - 1; i++) {
		strcat(body_data_buffer, body_data[i]);
		strcat(body_data_buffer, "&");
		body_data_size += strlen(body_data[i]);
        body_data_size++; // '&'
	}
	strcat(body_data_buffer, body_data[body_data_fields_count - 1]);
	body_data_size += strlen(body_data[body_data_fields_count - 1]);

	memset(line, 0, LINELEN);
	sprintf(line, "Content-Type: %s", content_type);
	compute_message(message, line);

	memset(line, 0, LINELEN);
	sprintf(line, "Content-Length: %d", body_data_size);
	compute_message(message, line);

	if (cookies != NULL) {
		memset(line, 0, LINELEN);
    	strcat(line, "Cookie: ");

		for (int i = 0; i < cookies_count - 1; i++) {
			strcat(line, cookies[i]);
            strcat(line, ";");
		}
		strcat(line, cookies[cookies_count - 1]);
        compute_message(message,line);
	}

	if (token != NULL) {
		memset(line, 0, LINELEN);
		sprintf(line, "Authorization: Bearer %s", token);
		compute_message(message, line);
	}

	compute_message(message, "");

    strcat(message, body_data_buffer);

	free(body_data_buffer);
	free(line);
	return message;
}

char *compute_get_request(char* host, char* url, char* query_params,
						char** cookies, int cookies_count, char* token) {
	char* message = calloc(BUFLEN, sizeof(char));
	char* line = calloc(LINELEN, sizeof(char));

	if (query_params != NULL) {
		sprintf(line, "GET %s?%s HTTP/1.1", url, query_params);
	} else {
		sprintf(line, "GET %s HTTP/1.1", url);
	}
	compute_message(message, line);

	memset(line, 0, LINELEN);
	sprintf(line, "Host: %s", host);
	compute_message(message, line);

	if (cookies != NULL) {
		memset(line, 0, LINELEN);
		strcat(line, "Cookie: ");

		for (int i = 0; i < cookies_count - 1; i++) {
			strcat(line, cookies[i]);
            strcat(line, ";");
		}
		strcat(line, cookies[cookies_count - 1]);
        compute_message(message, line);
	}

	if (token != NULL) {
		memset(line, 0, LINELEN);
		sprintf(line, "Authorization: Bearer %s", token);
		compute_message(message, line);
	}

	compute_message(message, "");

	free(line);
	return message;
}

char *compute_delete_request(char* host, char* url, char* query_params,
						char** cookies, int cookies_count, char* token) {
	char* message = calloc(BUFLEN, sizeof(char));
	char* line = calloc(LINELEN, sizeof(char));

	if (query_params != NULL) {
		sprintf(line, "DELETE %s?%s HTTP/1.1", url, query_params);
	} else {
		sprintf(line, "DELETE %s HTTP/1.1", url);
	}
	compute_message(message, line);

	memset(line, 0, LINELEN);
	sprintf(line, "Host: %s", host);
	compute_message(message, line);

	if (cookies != NULL) {
		memset(line, 0, LINELEN);
		strcat(line, "Cookie: ");

		for (int i = 0; i < cookies_count - 1; i++) {
			strcat(line, cookies[i]);
            strcat(line, ";");
		}
		strcat(line, cookies[cookies_count - 1]);
        compute_message(message, line);
	}

	if (token != NULL) {
		memset(line, 0, LINELEN);
		sprintf(line, "Authorization: Bearer %s", token);
		compute_message(message, line);
	}

	compute_message(message, "");

	free(line);
	return message;
}
