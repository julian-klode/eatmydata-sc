CFLAGS += -Wall -Wextra -std=c99 $(shell pkg-config --cflags libseccomp)
LDLIBS += $(shell pkg-config --libs libseccomp)

all: eatmydata-sc
	sudo setcap cap_sys_admin+ep eatmydata-sc

clean:
	rm -f eatmydata-sc
