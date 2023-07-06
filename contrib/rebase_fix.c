#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>

/*
 * Often while rebasing, the git merge algorithm will leave these
 * annoying diffs totally unmerged. For example:

<<<<<<< HEAD
=======
	case WIRE_SPLICE:
	case WIRE_SPLICE_ACK:
	case WIRE_SPLICE_LOCKED:
>>>>>>> e52991cee (channeld: Code to implement splicing)

 * There is no actual merge conflict in these cases, as no code is
 * being deleted, there is only code being added.
 *
 * This program finds these instances and just takes whatever is
 * there as the correct answer and removes all the diff lines.
 * In this example lines one, two, and six will be deleted.
 *
 * If a file only had these differences and no others, the filename
 * will be output of the program. You will typically want to throw
 * these results into git add.
 *
 * Here's how to use it:
 * 
 * 1) Be in the repo working directory
 * 2) Do the rebase that fails ie: git rebase offical/master
 * 3) Then run these commands:

gcc rebase_fix.c -o rebase_fix
git add $(./rebase_fix $(git ls-files -u  | cut -f 2 | sort -u))

 * Now all of the empty diffs will be gone and files that only had
 * empty diffs will be automatically staged with git add.
 *
 * Note: you can pass --dry-run as the first paramter to have it
 * output the results without changing any files.
*/

enum state {
	NORMAL,
	IN_FIRST_CHANGE,
	IN_SECOND_CHANGE,
	STATE_MAX
};

const char *state_jumpers[] =
{
	"<<<<<<< ",
	"=======",
	">>>>>>> ",
};

static char *sgets(char **ptr, int *len)
{
	*len = 0;
	char *result = *ptr;

	if(!**ptr)
		return NULL;

	while(**ptr != '\n' && **ptr != 0) {
		++*ptr;
		++*len;
	}

	if(**ptr == '\n') {
		++*len;
		++*ptr;
	}

	return result;
}

int main(int argc, char *argv[])
{
	int fd;
	int unfixable = 0;
	int file_size;
	int first_change_lines;
	int second_change_lines;
	enum state state;
	char *line_addr, *first_line, *middle_line, *last_line;
	int line_len, first_line_len, middle_line_len, last_line_len;
	char *addr;
	char *ptr;
	char *end;
	int addr_index;
	struct stat st;
	int dry_run = 0;

	for(int i = 1; i < argc; i++) {

		if(i == 1 && strcmp(argv[i], "--dry-run") == 0) {
			continue;
			dry_run = 1;
		}

		unfixable = 0;
		first_change_lines = 0;
		second_change_lines = 0;
		state = NORMAL;
		last_line = NULL;

		if(stat(argv[i], &st) != 0)
			return -1;

		file_size = st.st_size;

		fd = open(argv[i], O_RDWR);

		addr_index = 0;
		addr = mmap(NULL, file_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
		ptr = addr;

		if(addr == MAP_FAILED) {
			perror("Error in mmap");
			return -1;
		}

		while((line_addr = sgets(&ptr, &line_len))) {

			int jumper_len = strlen(state_jumpers[state]);
			if(jumper_len > line_len)
				continue;
			if(strncmp(state_jumpers[state], line_addr, jumper_len)) {
				if(state == IN_FIRST_CHANGE)
					first_change_lines++;
				if(state == IN_SECOND_CHANGE)
					second_change_lines++;
				last_line = line_addr;
				last_line_len = line_len;
				continue;
			}
			if(state == NORMAL) {
				first_line = line_addr;
				first_line_len = line_len;
			}
			if(state == IN_FIRST_CHANGE) {
				middle_line = line_addr;
				middle_line_len = line_len;
			}
			if(state == IN_SECOND_CHANGE) {
				if(first_change_lines && second_change_lines) {
					unfixable++;
				}
				else if(!second_change_lines) {
					// Remove second change area
					memmove(last_line, ptr, file_size - (ptr - addr));
					file_size -= line_len + last_line_len;
					ptr -= line_len + last_line_len;

					char *good_changes = first_line + first_line_len;
					// Remove first change line
					memmove(first_line, good_changes, file_size - (good_changes - addr));
					file_size -= good_changes - first_line;
					ptr -= good_changes - first_line;
				}
				else {
					// Remove the last change line
					memmove(line_addr, ptr, file_size - (ptr - addr));
					file_size -= line_len;
					ptr -= line_len;

					char *good_changes = middle_line + middle_line_len;
					// Remove first change area
					memmove(first_line, good_changes, file_size - (good_changes - addr));
					file_size -= first_line_len + middle_line_len;
					ptr -= first_line_len + middle_line_len;
				}
				first_change_lines = 0;
				second_change_lines = 0;
			}
			state = (state + 1) % STATE_MAX;
			last_line = line_addr;
			last_line_len = line_len;
		}

		if(!dry_run) {
			if((msync(addr, st.st_size, MS_SYNC)) < 0)
				perror("Error in msync");

			if (munmap(addr, st.st_size) == -1)
				perror("Error in munmap");

			if(ftruncate(fd, file_size) != 0)
				perror("Error in ftruncate");
		}

		close(fd);

		if(!unfixable)
			printf("%s\n", argv[i]);
	}

	return 0;
}