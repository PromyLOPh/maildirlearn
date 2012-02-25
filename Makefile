CFLAGS=-Wall -O3 -march=native

maildirlearn: maildirlearn.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $<

clean:
	$(RM) -f maildirlearn

