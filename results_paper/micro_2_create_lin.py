#!/usr/bin/python3

import matplotlib
from matplotlib import pyplot as plt
from csv import DictReader

create = {}
create[1000] = []
create[2000] = []
create[3000] = []
create[4000] = []
rsa = []

p = [100000, 500000, 1000000]

# read IBBE-SGX
with open("2_create.csv") as f:
    for line in f:
        items = line.split(',')
        if (int(items[2]) in p):
            create[int(items[3])].append(float(items[4]))

# read PKI
with open("rsa_all.csv") as f:
    for line in f:
        items = line.split(',')
        if (items[1] == "REMOVE"):
            if (int(items[2]) in p):
                rsa.append(float(items[4]))

p_text = ["100k", "500k", "1M"]
y_text = []

print(create[1000])


fig, ax1 = plt.subplots(figsize=(3,6))

ax1 = plt.subplot(311)
ax1.plot(p, create[1000], '--', marker="v", markersize=8, label="IBBE-SGX-1000")
ax1.plot(p, create[2000], '--', marker="o", markersize=8, label = "IBBE-SGX-2000")
ax1.plot(p, create[3000], '--', marker="^", markersize=8, label = "IBBE-SGX-3000")
ax1.plot(p, create[4000], '--', marker="+", markersize=8, label = "IBBE-SGX-4000")
ax1.plot(p, rsa, marker="s", markersize=8, label = "HE")

#ax1.set_xlabel('group size')
ax1.set_ylabel('create (s)')

#ax1.set_yscale('log')
#ax1.set_xscale('log')

plt.setp(ax1.get_xticklabels(), visible=False)

plt.xticks(p, p_text)
plt.ylim(0,3.5)

#plt.yticks([0.001, 0.01, 0.1, 1, 5], ["", "0.01", "0.1", "1", "5"])

# ----------------------------------------------------------
# REMOVE
remove = {}
remove[1000] = []
remove[2000] = []
remove[3000] = []
remove[4000] = []
rsa_remove = []

with open("4_remove.csv") as f:
    for line in f:
        items = line.split(',')
        if (int(items[2]) in p):
            remove[int(items[3])].append(float(items[4]))

# read PKI
with open("rsa_all.csv") as f:
    for line in f:
        items = line.split(',')
        if (items[1] == "REMOVE"):
            if (int(items[2]) in p):
                rsa_remove.append(float(items[4]))

ax2 = plt.subplot(312, sharex=ax1)
ax2.plot(p, remove[1000], '--', marker="v", markersize=8, label="IBBE-SGX-1000")
ax2.plot(p, remove[2000], '--', marker="o", markersize=8, label = "IBBE-SGX-2000")
ax2.plot(p, remove[3000], '--', marker="^", markersize=8, label = "IBBE-SGX-3000")
ax2.plot(p, remove[4000], '--', marker="+", markersize=8, label = "IBBE-SGX-4000")
ax2.plot(p, rsa_remove, marker="s", markersize=8, label = "HE")

ax2.set_ylabel('remove (s)')

#ax2.set_yscale('log')
#ax2.set_xscale('log')

plt.setp(ax2.get_xticklabels(), visible=False)

#ax1.set_yticks()

#plt.xticks(p, p_text)
#plt.yticks([0.001, 0.01, 0.1, 1, 5], ["", "0.01", "0.1", "1", "5"])
plt.ylim(0,3.5)

# ----------------------------------------------------------
# STORAGE
storage = {}
storage[1000] = []
storage[2000] = []
storage[3000] = []
storage[4000] = []
rsa_storage = []

# read IBBE-SGX
with open("2_create.csv") as f:
    for line in f:
        items = line.split(',')
        if (int(items[2]) in p):
            storage[int(items[3])].append(float(items[5]) / 1024)

# read PKI
with open("rsa_all.csv") as f:
    for line in f:
        items = line.split(',')
        if (items[1] == "CREATE"):
            if (int(items[2]) in p):
                rsa_storage.append(float(items[5]) / 1024)


ax3 = plt.subplot(313, sharex=ax1)
ax3.plot(p, storage[1000], '--', marker="v", markersize=8, label="IBBE-SGX-1000")
ax3.plot(p, storage[2000], '--', marker="o", markersize=8, label = "IBBE-SGX-2000")
ax3.plot(p, storage[3000], '--', marker="^", markersize=8, label = "IBBE-SGX-3000")
ax3.plot(p, storage[4000], '--', marker="+", markersize=8, label = "IBBE-SGX-4000")
ax3.plot(p, rsa_storage, marker="s", markersize=8, label = "HE")


#ax3.set_yscale('log')
#ax3.set_xscale('log')

plt.xticks(p, p_text)
#plt.yticks([1, 1024, 1024*200], ["1 KB", "1 MB", ".2 GB"])


ax3.set_ylabel('footprint (B)')
ax3.set_xlabel('group size')

#ax1.set_yticks()

axes = plt.gca()
#axes.set_xlim([0.7,4.3])
plt.ylim(0,512)
plt.xlim(0, 1100000)
#plt.grid()


plt.tight_layout()
plt.show()
