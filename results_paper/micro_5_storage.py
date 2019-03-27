
import matplotlib
from matplotlib import pyplot as plt
from csv import DictReader

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
        storage[int(items[3])].append(float(items[5]) / 1024)

# read PKI
with open("rsa_all.csv") as f:
    for line in f:
        items = line.split(',')
        if (items[1] == "CREATE"):
            rsa_storage.append(float(items[5]) / 1024)


p_text = ["1k", "5k", "10k", "50k", "100k", "500k", "1M"]
y_text = []
p = [1, 2, 3, 4, 5, 6, 7]

fig, ax1 = plt.subplots(figsize=(4,2.5))
ax1.plot(p, storage[1000], '--', marker="v", markersize=8)
ax1.plot(p, storage[2000], marker="o", markersize=8)
ax1.plot(p, storage[3000], '-', marker="^", markersize=8)
ax1.plot(p, storage[4000], '--', marker="+", markersize=8)
ax1.plot(p, rsa_storage, '--', marker="+", markersize=8)

ax1.set_xlabel('group size')
ax1.set_ylabel('group metadata')

ax1.set_yscale('log')
#ax1.set_yticks()

plt.xticks(p, p_text)
plt.yticks([1, 1024, 1024*256], ["1 KB", "1 MB", "256 MB"])

axes = plt.gca()
#axes.set_xlim([0.7,4.3])

plt.grid()


plt.tight_layout()
plt.show()
