BINDIR = assets/build
CC     = gcc
CFLAGS = -Wall -Wextra -O2 -DASSETS_DIR=\"assets\"

.PHONY: all clean

all: \
    $(BINDIR)/azazel_implant.so \
    $(BINDIR)/orbit_implant.so \
    $(BINDIR)/mirai_sim \
    $(BINDIR)/syslogk_sim \
    $(BINDIR)/reptile_sim \
    $(BINDIR)/bpf_backdoor \
    $(BINDIR)/c2_beacon \
    $(BINDIR)/skidmap_sim \
    $(BINDIR)/miner_sim \
    $(BINDIR)/team_tnt_sim \
    $(BINDIR)/multi_stage_loader \
    $(BINDIR)/pause_binary \
    $(BINDIR)/cred_scrape_v2

$(BINDIR):
	mkdir -p $(BINDIR)

$(BINDIR)/azazel_implant.so: assets/src/azazel_implant.c | $(BINDIR)
	$(CC) -shared -fPIC -o $@ $^ -ldl

$(BINDIR)/orbit_implant.so: assets/src/orbit_implant.c | $(BINDIR)
	$(CC) -shared -fPIC -o $@ $^ -ldl

$(BINDIR)/mirai_sim: assets/src/mirai_sim.c assets/src/lab_common.c | $(BINDIR)
	$(CC) $(CFLAGS) -o $@ $^

$(BINDIR)/syslogk_sim: assets/src/syslogk_sim.c assets/src/lab_common.c | $(BINDIR)
	$(CC) $(CFLAGS) -o $@ $^

$(BINDIR)/reptile_sim: assets/src/reptile_sim.c assets/src/lab_common.c | $(BINDIR)
	$(CC) $(CFLAGS) -o $@ $^

$(BINDIR)/bpf_backdoor: assets/src/bpf_backdoor.c assets/src/lab_common.c | $(BINDIR)
	$(CC) $(CFLAGS) -o $@ $^

$(BINDIR)/c2_beacon: assets/src/c2_beacon.c assets/src/lab_common.c | $(BINDIR)
	$(CC) $(CFLAGS) -o $@ $^

$(BINDIR)/skidmap_sim: assets/src/skidmap_sim.c assets/src/lab_common.c | $(BINDIR)
	$(CC) $(CFLAGS) -o $@ $^

$(BINDIR)/miner_sim: assets/src/miner_sim.c assets/src/lab_common.c | $(BINDIR)
	$(CC) $(CFLAGS) -o $@ $^

$(BINDIR)/team_tnt_sim: assets/src/team_tnt_sim.c assets/src/lab_common.c | $(BINDIR)
	$(CC) $(CFLAGS) -o $@ $^

$(BINDIR)/multi_stage_loader: assets/src/multi_stage_loader.c assets/src/lab_common.c | $(BINDIR)
	$(CC) $(CFLAGS) -o $@ $^

$(BINDIR)/pause_binary: assets/src/pause_binary.c | $(BINDIR)
	$(CC) $(CFLAGS) -o $@ $^

$(BINDIR)/cred_scrape_v2: assets/src/cred_scrape_v2.c | $(BINDIR)
	$(CC) $(CFLAGS) -o $@ $^

clean:
	rm -rf $(BINDIR)

# $(BINDIR)/ptrace_inject: assets/src/unused/ptrace_inject.c assets/src/lab_common.c | $(BINDIR)
# 	$(CC) $(CFLAGS) -o $@ $^
# $(BINDIR)/ptrace_inject_v2: assets/src/unused/ptrace_inject_v2.c assets/src/lab_common.c | $(BINDIR)
# 	$(CC) $(CFLAGS) -o $@ $^
# $(BINDIR)/process_hollow: assets/src/unused/process_hollow.c assets/src/lab_common.c | $(BINDIR)
# 	$(CC) $(CFLAGS) -o $@ $^
# $(BINDIR)/deleted_exe: assets/src/unused/deleted_exe.c assets/src/lab_common.c | $(BINDIR)
# 	$(CC) $(CFLAGS) -o $@ $^
# $(BINDIR)/fileless_exec: assets/src/unused/fileless_exe.c assets/src/lab_common.c | $(BINDIR)
# 	$(CC) $(CFLAGS) -o $@ $^
# $(BINDIR)/fileless_shm: assets/src/unused/fileless_shm.c assets/src/lab_common.c | $(BINDIR)
# 	$(CC) $(CFLAGS) -o $@ $^ -lrt
# $(BINDIR)/polymorphic_shellcode: assets/src/unused/polymorphic_shellcode.c assets/src/lab_common.c | $(BINDIR)
# 	$(CC) $(CFLAGS) -o $@ $^
# $(BINDIR)/ld_preload_installer: assets/src/unused/ld_preload_installer.c assets/src/lab_common.c | $(BINDIR)
# 	$(CC) $(CFLAGS) -o $@ $^ -ldl
# $(BINDIR)/ld_preload_rootkit.so: assets/src/unused/ld_preload_rootkit.c | $(BINDIR)
# 	$(CC) -shared -fPIC -o $@ $^ -ldl
# $(BINDIR)/systemd_backdoor: assets/src/unused/systemd_backdoor.c assets/src/lab_common.c | $(BINDIR)
# 	$(CC) $(CFLAGS) -o $@ $^
# $(BINDIR)/evil.so: assets/src/unused/evil.c | $(BINDIR)
# 	$(CC) -shared -fPIC -o $@ $^