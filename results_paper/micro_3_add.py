
import matplotlib
import numpy as np
from csv import DictReader

import numpy as np
import matplotlib.pyplot as plt
from matplotlib import mlab

x = []
with open("3_add_new.csv") as f:
    for line in f:
        items = line.split(',')
        x.append(float(items[4]) * 1000)

x_pki = []
# read PKI
with open("rsa_all.csv") as f:
    for line in f:
        items = line.split(',')
        if (items[1] == "ADD"):
            x_pki.append(float(items[4]) * 1000)


n_bins = 50

fig, ax1 = plt.subplots(figsize=(3,2.5))

n, bins, patches = ax1.hist(x, n_bins, normed=1, label = "IBBE-SGX",
                            histtype='step', cumulative=True)

n2, bins2, patches2 = ax1.hist(x_pki, n_bins, normed=1, label="HE",
                            linestyle='dashed',
                            histtype='step', cumulative=True)

ax1.set_xlabel('latency (ms)')
ax1.set_ylabel('CDF')

axes = plt.gca()
axes.set_xlim([0,5])
#ax1.set_xticks([0, 0.5, 1, 1.5])

#ax.legend(loc='upper center', bbox_to_anchor=(0.5, -0.05),  shadow=True, ncol=2)

#lgd = plt.legend(bbox_to_anchor=(1.07, 1), loc='upper left')
#plt.gcf().canvas.draw()
#invFigure = plt.gcf().transFigure.inverted()
#lgd_pos = lgd.get_window_extent()
#lgd_coord = invFigure.transform(lgd_pos)
#lgd_xmax = lgd_coord[1, 0]
#ax_pos = plt.gca().get_window_extent()
#ax_coord = invFigure.transform(ax_pos)
#ax_xmax = ax_coord[1, 0]
#shift = 1 - (lgd_xmax - ax_xmax)
#plt.gcf().tight_layout(rect=(0, 0, shift, 1))

#plt.grid()
#plt.legend()

plt.tight_layout()

plt.show()
