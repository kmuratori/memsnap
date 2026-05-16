BINDIR = assets/build
CC     = gcc
CFLAGS = -Wall -Wextra -O2 -DASSETS_DIR=\"assets\"

.PHONY: all clean

all: $(BINDIR)/ptrace_inject $(BINDIR)/process_hollow $(BINDIR)/deleted_exe \
     $(BINDIR)/fileless_exec $(BINDIR)/miner_sim $(BINDIR)/evil.so \
     $(BINDIR)/c2_beacon $(BINDIR)/cred_scrape_v2 $(BINDIR)/fileless_shm \
     $(BINDIR)/polymorphic_shellcode $(BINDIR)/multi_stage_loader \
     $(BINDIR)/ld_preload_installer $(BINDIR)/systemd_backdoor \
     $(BINDIR)/ptrace_inject_v2 $(BINDIR)/pause_binary \
     $(BINDIR)/ld_preload_rootkit.so $(BINDIR)/bpf_backdoor \
     $(BINDIR)/azazel_implant.so $(BINDIR)/skidmap_sim \
     $(BINDIR)/reptile_sim $(BINDIR)/syslogk_sim \
     $(BINDIR)/mirai_sim $(BINDIR)/team_tnt_sim \
     $(BINDIR)/orbit_implant.so

$(BINDIR):
	mkdir -p $(BINDIR)

$(BINDIR)/ptrace_inject: assets/src/ptrace_inject.c assets/src/lab_common.c | $(BINDIR)
	$(CC) $(CFLAGS) -o $@ $^

$(BINDIR)/process_hollow: assets/src/process_hollow.c assets/src/lab_common.c | $(BINDIR)
	$(CC) $(CFLAGS) -o $@ $^

$(BINDIR)/deleted_exe: assets/src/deleted_exe.c assets/src/lab_common.c | $(BINDIR)
	$(CC) $(CFLAGS) -o $@ $^

$(BINDIR)/fileless_exec: assets/src/fileless_exe.c assets/src/lab_common.c | $(BINDIR)
	$(CC) $(CFLAGS) -o $@ $^

$(BINDIR)/miner_sim: assets/src/miner_sim.c assets/src/lab_common.c | $(BINDIR)
	$(CC) $(CFLAGS) -o $@ $^

$(BINDIR)/evil.so: assets/src/evil.c | $(BINDIR)
	$(CC) -shared -fPIC -o $@ $^

clean:
	rm -rf $(BINDIR)

$(BINDIR)/c2_beacon: assets/src/c2_beacon.c assets/src/lab_common.c | $(BINDIR)
	$(CC) $(CFLAGS) -o $@ $^

$(BINDIR)/cred_scrape_v2: assets/src/cred_scrape_v2.c assets/src/lab_common.c | $(BINDIR)
	$(CC) $(CFLAGS) -o $@ $^ -ldl

$(BINDIR)/fileless_shm: assets/src/fileless_shm.c assets/src/lab_common.c | $(BINDIR)
	$(CC) $(CFLAGS) -o $@ $^ -lrt

$(BINDIR)/polymorphic_shellcode: assets/src/polymorphic_shellcode.c assets/src/lab_common.c | $(BINDIR)
	$(CC) $(CFLAGS) -o $@ $^

$(BINDIR)/multi_stage_loader: assets/src/multi_stage_loader.c assets/src/lab_common.c | $(BINDIR)
	$(CC) $(CFLAGS) -o $@ $^

$(BINDIR)/ld_preload_installer: assets/src/ld_preload_installer.c assets/src/lab_common.c | $(BINDIR)
	$(CC) $(CFLAGS) -o $@ $^ -ldl

$(BINDIR)/systemd_backdoor: assets/src/systemd_backdoor.c assets/src/lab_common.c | $(BINDIR)
	$(CC) $(CFLAGS) -o $@ $^

$(BINDIR)/ptrace_inject_v2: assets/src/ptrace_inject_v2.c assets/src/lab_common.c | $(BINDIR)
	$(CC) $(CFLAGS) -o $@ $^

$(BINDIR)/pause_binary: assets/src/pause_binary.c | $(BINDIR)
	$(CC) $(CFLAGS) -o $@ $^

$(BINDIR)/ld_preload_rootkit.so: assets/src/ld_preload_rootkit.c | $(BINDIR)
	$(CC) -shared -fPIC -o $@ $^ -ldl

$(BINDIR)/bpf_backdoor: assets/src/bpf_backdoor.c assets/src/lab_common.c | $(BINDIR)
	$(CC) $(CFLAGS) -o $@ $^

$(BINDIR)/azazel_implant.so: assets/src/azazel_implant.c | $(BINDIR)
	$(CC) -shared -fPIC -o $@ $^ -ldl

$(BINDIR)/skidmap_sim: assets/src/skidmap_sim.c assets/src/lab_common.c | $(BINDIR)
	$(CC) $(CFLAGS) -o $@ $^

$(BINDIR)/reptile_sim: assets/src/reptile_sim.c assets/src/lab_common.c | $(BINDIR)
	$(CC) $(CFLAGS) -o $@ $^

$(BINDIR)/syslogk_sim: assets/src/syslogk_sim.c assets/src/lab_common.c | $(BINDIR)
	$(CC) $(CFLAGS) -o $@ $^

$(BINDIR)/mirai_sim: assets/src/mirai_sim.c assets/src/lab_common.c | $(BINDIR)
	$(CC) $(CFLAGS) -o $@ $^

$(BINDIR)/team_tnt_sim: assets/src/team_tnt_sim.c assets/src/lab_common.c | $(BINDIR)
	$(CC) $(CFLAGS) -o $@ $^

$(BINDIR)/orbit_implant.so: assets/src/orbit_implant.c | $(BINDIR)
	$(CC) -shared -fPIC -o $@ $^ -ldl
