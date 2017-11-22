
Debian
====================
This directory contains files used to package ladacoind/ladacoin-qt
for Debian-based Linux systems. If you compile ladacoind/ladacoin-qt yourself, there are some useful files here.

## ladacoin: URI support ##


ladacoin-qt.desktop  (Gnome / Open Desktop)
To install:

	sudo desktop-file-install Ladacoin.desktop
	sudo update-desktop-database

If you build yourself, you will either need to modify the paths in
the .desktop file or copy or symlink your ladacoin-qt binary to `/usr/bin`
and the `../../share/pixmaps/bitcoin128.png` to `/usr/share/pixmaps`

ladacoin-qt.protocol (KDE)

