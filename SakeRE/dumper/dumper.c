#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <unistd.h>
#include <libgen.h>

#define MAX_LINE_LENGTH 1024

int dump_pid_map_info(int pid, int line_index);
int dump_memory_to_file(int pid, unsigned long start_address, unsigned long end_address);

char *get_program_directory() {
    char path[MAX_LINE_LENGTH];
    
    // Read the symbolic link "/proc/self/exe" to get the program's executable path
    ssize_t len = readlink("/proc/self/exe", path, sizeof(path) - 1);
    if (len == -1) {
        perror("readlink");
        return NULL;
    }

    path[len] = '\0';  // Null-terminate the path string

    // Get the directory part of the path
    char *dir = dirname(path);
    return dir;
}

// Function to get the start and end addresses from the /proc/{pid}/maps
int dump_pid_map_info(int pid, int line_index) {
    char filename[256];
    snprintf(filename, sizeof(filename), "/proc/%d/maps", pid);

    FILE *file = fopen(filename, "r");
    if (!file) {
        perror("Error opening /proc/[pid]/maps");
        return -1;
    }

    char line[MAX_LINE_LENGTH];
    int current_line = 0;

    // Read each line from the /proc/{pid}/maps
    while (fgets(line, sizeof(line), file)) {
        // Skip empty lines or lines that don't contain valid address ranges
        if (line[0] == '\0' || line[0] == '\n') {
            continue;
        }

        // If the current line matches the line_index, extract the addresses
        if (current_line == line_index) {
            unsigned long start_address, end_address;

            // Parse the line to extract start and end addresses
            if (sscanf(line, "%lx-%lx", &start_address, &end_address) == 2) {
                printf("PID: %d, Line (0 offset) %d: Start Address: 0x%lx, End Address: 0x%lx\n",
                       pid, line_index, start_address, end_address);
                fclose(file);

                // Call the function to open the memory and save it to output.bin
                if (dump_memory_to_file(pid, start_address, end_address) != 0) {
                    return -1;
                }
                return 0;
            } else {
                fprintf(stderr, "Error parsing address range from line %d\n", line_index);
                fclose(file);
                return -1;
            }
        }

        current_line++;
    }

    // If the line_index was not found
    fprintf(stderr, "Line %d not found in /proc/%d/maps\n", line_index, pid);
    fclose(file);
    return -1;
}

// Function to open memory of the process and save to output.bin
int dump_memory_to_file(int pid, unsigned long start_address, unsigned long end_address) {
    // Open /proc/[pid]/mem to read the memory of the process
    char mem_filename[256];
    snprintf(mem_filename, sizeof(mem_filename), "/proc/%d/mem", pid);

    FILE *mem_file = fopen(mem_filename, "rb");
    if (!mem_file) {
        perror("Error opening /proc/[pid]/mem");
        return -1;
    }

    // Seek to the start address of the memory region
    if (fseek(mem_file, start_address, SEEK_SET) != 0) {
        perror("Error seeking to start address in /proc/[pid]/mem");
        fclose(mem_file);
        return -1;
    }

    // Calculate the size of the memory region
    size_t size = end_address - start_address;

    // Get the directory of the original binary
    char *dir = get_program_directory();

    // Construct the full output file path next to the original binary
    char output_file_path[512];
    snprintf(output_file_path, sizeof(output_file_path), "%s/output.bin", dir);

    // Open output file for writing the memory content
    FILE *output_file = fopen(output_file_path, "wb");
    if (!output_file) {
        perror("Error opening output.bin");
        fclose(mem_file);
        return -1;
    }

    // Read the memory region and write it to the output file
    unsigned char *buffer = malloc(size);
    if (!buffer) {
        perror("Error allocating memory buffer");
        fclose(mem_file);
        fclose(output_file);
        return -1;
    }

    size_t read_size = fread(buffer, 1, size, mem_file);
    if (read_size != size) {
        fprintf(stderr, "Error reading memory region: expected %zu bytes, but got %zu bytes\n", size, read_size);
        free(buffer);
        fclose(mem_file);
        fclose(output_file);
        return -1;
    }

    // Write the buffer to the output file
    if (fwrite(buffer, 1, size, output_file) != size) {
        perror("Error writing to output.bin");
        free(buffer);
        fclose(mem_file);
        fclose(output_file);
        return -1;
    }

    printf("Memory region successfully written to %s\n", output_file_path);

    // Clean up
    free(buffer);
    fclose(mem_file);
    fclose(output_file);

    return 0;
}

int main(int argc, char *argv[]) {
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <pid> <line_index>\n", argv[0]);
        return EXIT_FAILURE;
    }

    int pid = atoi(argv[1]);
    int line_index = atoi(argv[2]);

    return dump_pid_map_info(pid, line_index);
}
