#include <stdio.h>
#include <string.h>

int main(void) {
    char input[256];

    // List of available labs
    printf("Available labs:\n");
    printf("  - first-try\n");
    printf("\nEnter a lab: ");

    if (fgets(input, sizeof(input), stdin) != NULL) {
        input[strcspn(input, "\n")] = 0;

        if (strlen(input) == 0) {
            fprintf(stderr, "No lab name provided.\n");
            return 1;
        }

        if (strcmp(input, "first-try") == 0) {
            printf("Running: %s\n", input);
            return 0;
        } else {
            fprintf(stderr, "Unknown lab: %s\n", input);
            return 1;
        }
    } else {
        fprintf(stderr, "Input error\n");
        return 1;
    }
}