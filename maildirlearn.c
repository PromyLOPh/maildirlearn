/*
Copyright (c) 2012
	Lars-Dominik Braun <lars@6xq.net>

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
*/

/* strdup */
#define _BSD_SOURCE

#include <sys/types.h>
#include <regex.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/wait.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include <stdbool.h>
#include <sys/inotify.h>
#include <sys/types.h>
#include <dirent.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stddef.h>

/* spam status (tri-state + unknown) */
typedef enum {UNKNOWN, SPAM, HAM, UNSURE} status_t;

/* linked list */
struct wdpath {
	struct wdpath *next;
	/* inotify watch fd */
	int wd;
	/* relative path */
	char *path;
};
typedef struct wdpath wdpath_t;

/* recursive dir reading, linked list */
struct notifyDirread {
	struct notifyDirread *next;
	wdpath_t *wdp;
	DIR *dir;
};
typedef struct notifyDirread notifyDirread_t;

typedef struct {
	/* inotify fd */
	int fd;

	/* wd hash table */
	wdpath_t **tbl;
	/* hash table size */
	size_t len;

	/* “root” dir we’re watching */
	char *basedir;

	char buf[sizeof (struct inotify_event)+1024];
	/* can’t use the same buf for real and simulated events */
	char direvbuf[sizeof (struct inotify_event)+1024];
	size_t filled, read;

	/* linked list and last element of linked list (O(1) append) */
	notifyDirread_t *dir, *lastdir;
} notify_t;

/*	watch descriptor to hash
 */
static unsigned int notifyHash (const notify_t *n, const int wd) {
	assert (n != NULL);

	return wd % n->len;
}

/*	delete watch descriptor from hashtable
 */
static bool notifyTblDel (notify_t *n, const int wd) {
	unsigned int h;
	wdpath_t *cur, *prev;

	assert (n != NULL);

	h = notifyHash (n, wd);
	cur = n->tbl[h];
	prev = cur;

	while (cur != NULL) {
		if (cur->wd == wd) {
			if (prev == cur) {
				/* remove first entry in list */
				n->tbl[h] = cur->next;
			} else {
				prev->next = cur->next;
			}
			printf ("[-] %i, %s\n", wd, cur->path);
			free (cur->path);
			free (cur);
			return true;
		}
		prev = cur;
		cur = cur->next;
	}

	return false;
}

/*	add watch descriptor and path to hash table
 */
static wdpath_t *notifyTblAdd (notify_t *n, const int wd, const char *relpath) {
	unsigned int h;
	wdpath_t *cur;

	assert (n != NULL);
	assert (relpath != NULL);

	h = notifyHash (n, wd);
	cur = n->tbl[h];

	if (cur != NULL) {
		while (cur->next != NULL) {
			if (cur->wd == wd) {
				/* already have this one */
				return cur;
			}
			cur = cur->next;
		}
		cur->next = malloc (sizeof (*cur->next));
		assert (cur->next != NULL);
		cur = cur->next;
	} else {
		cur = malloc (sizeof (*cur));
		assert (cur != NULL);
		n->tbl[h] = cur;
	}

	cur->wd = wd;
	cur->path = strdup (relpath);
	assert (cur->path != NULL);
	cur->next = NULL;

	printf ("[+] %i, %s\n", wd, relpath);

	return cur;
}

/*	create watch for relpath (relative to basedir)
 */
static bool notifyAdd (notify_t *n, const char *relpath) {
	char path[1024];
	int wd;
	wdpath_t *wdp;

	assert (n != NULL);
	assert (n->basedir != NULL);
	assert (relpath != NULL);

	if (snprintf (path, sizeof (path), "%s%s", n->basedir, relpath) >= sizeof (path)) {
		/* truncated */
		return false;
	}

	if ((wd = inotify_add_watch (n->fd, path, IN_CREATE | IN_MOVED_TO)) == -1) {
		perror ("inotify_add_watch");
		return false;
	}

	wdp = notifyTblAdd (n, wd, relpath);
	assert (wdp != NULL);

	/* set up recursion, append to list */
	notifyDirread_t *cur;
	if (n->lastdir == NULL) {
		n->dir = malloc (sizeof (*n->dir));
		cur = n->dir;
	} else {
		n->lastdir->next = malloc (sizeof (*n->lastdir->next));
		cur = n->lastdir->next;
	}
	cur->wdp = wdp;
	cur->dir = NULL;
	cur->next = NULL;
	n->lastdir = cur;

	return true;
}

/*	retrieve path from hash table
 */
static const wdpath_t *notifyTblGet (notify_t *n, const int wd) {
	unsigned int h;
	wdpath_t *cur;

	assert (n != NULL);

	h = notifyHash (n, wd);
	cur = n->tbl[h];

	while (cur != NULL) {
		if (cur->wd == wd) {
			return cur;
		}
		cur = cur->next;
	}

	return NULL;
}

/*	go to next dir in recursive dir list
 */
static void notifyDirNext (notify_t *n) {
	notifyDirread_t *next;

	closedir (n->dir->dir);

	next = n->dir->next;
	free (n->dir);
	n->dir = next;
	if (n->dir == NULL) {
		/* this was the last dir in the list */
		n->lastdir = NULL;
	}
}

/*	read next event and retrieve event/watch descriptor path structs
 */
static bool notifyRead (notify_t *n, const struct inotify_event **retEvent,
		const wdpath_t **retWdp) {
	struct inotify_event *event;
	const wdpath_t *wdp;

	assert (n != NULL);
	assert (retEvent != NULL);
	assert (retWdp != NULL);

	while (n->dir != NULL) {
		if (n->dir->dir != NULL) {
			/* continue reading open dir */
			struct dirent *dent;
			
			while (true) {
				dent = readdir (n->dir->dir);
				if (dent != NULL) {
					struct stat sb;
					char fullpath[1024];

					if (strcmp (dent->d_name, "..") == 0 || strcmp (dent->d_name, ".") == 0) {
						continue;
					}

					assert (n->dir->wdp != NULL);
					assert (n->dir->wdp->path != NULL);
					if (snprintf (fullpath, sizeof (fullpath), "%s%s%s", n->basedir,
							n->dir->wdp->path, dent->d_name) >= sizeof (fullpath)) {
						/* overflow */
						assert (0);
						continue;
					}

					if (stat (fullpath, &sb) == -1) {
						perror ("stat");
						continue;
					}
					if (!S_ISDIR (sb.st_mode)) {
						continue;
					}

					/* simulate create dir event */
					event = (struct inotify_event *) n->direvbuf;
					event->wd = n->dir->wdp->wd;
					event->mask = IN_CREATE | IN_ISDIR;
					strncpy (event->name, dent->d_name, sizeof (n->direvbuf)-sizeof (*event)-1);
					event->len = strlen (dent->d_name)+1;

					*retEvent = event;
					*retWdp = n->dir->wdp;
					return true;
				} else {
					notifyDirNext (n);
					break;
				}
				/* never reached */
				assert (0);
			}
		} else {
			char fullpath[1024];

			assert (n->dir != NULL && n->dir->wdp != NULL && n->dir->wdp->path != NULL);

			snprintf (fullpath, sizeof (fullpath), "%s%s", n->basedir,
					n->dir->wdp->path);
			n->dir->dir = opendir (fullpath);
			if (n->dir->dir == NULL) {
				notifyDirNext (n);
			}
		}
	}
	
	if (n->read >= n->filled) {
		ssize_t ret;

		if ((ret = read (n->fd, n->buf, sizeof (n->buf))) == -1) {
			perror ("read");
			return false;
		}

		n->read = 0;
		n->filled = ret;
	}

	event = (struct inotify_event *) (n->buf + n->read);
	n->read += sizeof (*event)+event->len;

	wdp = notifyTblGet (n, event->wd);
	if (wdp == NULL) {
		printf ("no wdp\n");
		return false;
	}

	*retEvent = event;
	*retWdp = wdp;

	return true;
}

/*	initialize notify struct: obtain inotify fd, add watch for basedir
 */
static bool notifyInit (notify_t *n, const size_t len, const char *basedir) {
	assert (n != NULL);
	assert (basedir != NULL);

	memset (n, 0, sizeof (*n));

	n->len = len;
	n->tbl = calloc (n->len, sizeof (*n->tbl));
	n->basedir = strdup (basedir);

	if ((n->fd = inotify_init ()) == -1) {
		perror ("inotify_init");
		return false;
	}

	return notifyAdd (n, "");
}

/*	get current bogofilter status, get desired status from path (via regex),
 *	set new bogofilter status
 */
static bool runBogofilter (const char *bogopath, const regex_t spamdirre,
		const char *path) {
	status_t curStatus = UNKNOWN, newStatus = UNKNOWN;
	pid_t pid;

	/* get current status */
	pid = fork ();
	if (pid == -1) {
		perror ("fork");
		return false;
	} else if (pid == 0) {
		/* child */
		if (execl (bogopath, bogopath, "-I", path, (char *) NULL) == -1) {
			perror ("execl");
			return false;
		}
		/* never reached */
		assert (0);
	} else {
		int status;

		if (waitpid (pid, &status, 0) == -1) {
			perror ("waitpid");
			return false;
		} else {
			/* translate bogofilter exit status to internal status */
			switch (WEXITSTATUS (status)) {
				case 2:
					printf ("curStatus=unsure\n");
					curStatus = UNSURE;
					break;

				case 1:
					printf ("curStatus=ham\n");
					curStatus = HAM;
					break;

				case 0:
					printf ("curStatus=spam\n");
					curStatus = SPAM;
					break;

				default:
					/* invalid status */
					return false;
					break;
			}
		}
	} /* end if fork() */

	/* user decided this is spam? */
	if (regexec (&spamdirre, path, 0, NULL, 0) == 0) {
		/* match */
		printf ("new status: spam\n");
		newStatus = SPAM;
	} else {
		printf ("new status: ham\n");
		newStatus = HAM;
	} /* end if regex */

	/* set new status */
	if (curStatus != newStatus) {
		const char *bogoopts = NULL;

		if (curStatus == UNSURE) {
			if (newStatus == HAM) {
				bogoopts = "-n";
			} else if (newStatus == SPAM) {
				bogoopts = "-s";
			}
		} else if (curStatus == SPAM && newStatus == HAM) {
			bogoopts = "-Sn";
		} else if (curStatus == HAM && newStatus == SPAM) {
			bogoopts = "-Ns";
		} else {
			assert (0);
		}

		pid = fork ();
		if (pid == -1) {
			perror ("fork");
		} else if (pid == 0) {
			/* child */
			if (execl (bogopath, bogopath, bogoopts, "-I", path,
					(char *) NULL) == -1) {
				perror ("execl");
				return false;
			}
			/* never reached */
			assert (0);
		} else {
			int status;

			if (waitpid (pid, &status, 0) == -1) {
				perror ("waitpid2");
				return false;
			} else {
				printf ("bogofilter returned %i\n", WEXITSTATUS (status));
			}
		}
	} /* end if curStatus != newStatus */

	return true;
}

int main (int argc, char **argv) {
	regex_t spamdirre, excludere;
	const char bogopath[] = "bogofilter";
	/* with '/' postfix */
	const char watchdir[] = "mail/";
	int running = 1;
	notify_t n;

	/* setup */
	notifyInit (&n, 128, watchdir);

	if (regcomp (&spamdirre, "mail/\\.Junk/", REG_EXTENDED) != 0) {
		printf ("invalid spamdir re\n");
	}

	if (regcomp (&excludere, "mail/(\\.Unsure/|[^/]+/(tmp|.*:2,[A-S]*T[U-Z]*$)|.*dovecot)", REG_EXTENDED) != 0) {
		printf ("invalid exclude re\n");
	}

	while (running) {
		const struct inotify_event *event;
		const wdpath_t *wdp;

		if (notifyRead (&n, &event, &wdp)) {
			char fullpath[1024], *relpath;

			assert (event != NULL);
			assert (wdp != NULL);

			/* a word of warning: don’t use event->name if event->len is 0! */
			if (snprintf (fullpath, sizeof (fullpath), "%s%s%s", n.basedir,
					wdp->path, (event->len == 0) ? "" : event->name) >= sizeof (fullpath)) {
				/* overflow */
				assert (0);
				continue;
			}
			relpath = fullpath + strlen (n.basedir);

			/* is path excluded? */
			if (regexec (&excludere, fullpath, 0, NULL, 0) == 0) {
				continue;
			}

			//printf ("[!] full: %s\n", fullpath);

			if (event->mask & IN_IGNORED || event->mask & IN_DELETE_SELF) {
				/* watch was removed */
				notifyTblDel (&n, event->wd);
			} else if (event->mask & IN_ISDIR) {
				/* FIXME: insane strncat */
				strncat (fullpath, "/", sizeof (fullpath)-strlen (fullpath)-1);
				notifyAdd (&n, relpath);
			} else {
				runBogofilter (bogopath, spamdirre, fullpath);
			}
		} else {
			printf ("notifyRead failed\n");
		}
	}

	regfree (&spamdirre);
	regfree (&excludere);
}
