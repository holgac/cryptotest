#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include "rypto.h"

struct command *construct_commands()
{
	struct command *root, *cur;
	root = malloc(sizeof(struct command));
	root->next = 0;
	root->child = 0;
	memset(root->cmd, 0, CMDLEN * sizeof(char));
	root->child = construct_shift_cmd();
	cur = root->child;
	cur->next = construct_affine_cmd();
	cur = cur->next;
	// cur->next = construct_other_cmd()
	// cur = cur->next;
	return root;
}

struct command *find_cmd(struct command *p, const char *str)
{
	struct command *t;
	for(t = p->child; t; t = t->next) {
		if(strcmp(t->cmd, str) == 0)
			return t;
	}
	return 0;
}

int main(int argc, char** argv)
{
	struct command *commands, *cmd;
	size_t i;
	if(argc < 2) {
		exit(0);
	}
	commands = construct_commands();
	cmd = commands;
	for(i=1;i<argc;++i) {
		struct command *c2;
		c2 = find_cmd(cmd, argv[i]);
		if(c2 == 0)
			break;
		cmd = c2;
	}
	if(cmd == 0) {
		printf("Cannot parse command\n");
		exit(0);
	}
	if(cmd->child != 0) {
		printf("This command has subcommands!\n");
		exit(0);
	}
	if(cmd->argcnt != (argc-i)) {
		printf("This command requires %u extra params\n", cmd->argcnt);
		exit(0);
	}
	cmd->perform(argc-i, argv+i);
	return 0;
}
