#include <stdlib.h>
#include <time.h>
#include <stdio.h>

int main(){
    // Get the current timestamp
    time_t t;
    time(&t);

    // Format the filename using the timestamp
    char filename[50];
    snprintf(filename, sizeof(filename), "/tmp/id_%ld.txt", t);

    // Run the command to write the output to the unique file
    char command[100];
    snprintf(command, sizeof(command), "id > %s", filename);
    system(command);

    return 0;
}
