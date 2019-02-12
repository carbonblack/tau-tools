#!/bin/bash

# OSX Shlayer Cleanup Script
# gfoss[at]carbonblack[.]com
# Feb 11, 2019

# Run automatically or interactively?
autoremove=false
if 	[[ "$1" == "--autoremove" ]]; then
	autoremove=true
fi

# When running interactively, display warning
if [[ $autoremove == "false" ]]; then
	echo ""
	echo "[[ WARNING - THIS SCRIPT WILL DELETE FILES! MAKE SURE THAT YOU ARE OKAY WITH THIS BEFORE PROCEEDING! ]]"
	echo -n "					Enter 'YES' to continue: "
	read shallWeContinue
	if [ $shallWeContinue != 'YES' ]; then
		echo ""
		exit 1
	fi
else
	echo ""
	echo "[[ WARNING - THIS SCRIPT WILL DELETE FILES! MAKE SURE THAT YOU ARE OKAY WITH THIS BEFORE PROCEEDING! ]]"
	echo "					Press CRTL+C to abort..."
	sleep 5
fi

# Set Directories
directories=("/tmp/*/Player*.app/"
		"/Applications/Mac*Cleanup*Pro*.app/"
		"/Volumes/Player/"
		"/Volumes/FlashPlayer/"
		"/private/tmp/*/Player/"
		"/private/var/folders/*/*/T/AppTranslocation/*/d/Player_*.app"
		"/private/var/folders/*/*/T/AppTranslocation/*/d/FashPlayer_*.app"
		"/private/var/folders/*/*/T/AppTranslocation/*/d/iZipFast_*.app"
		"/private/var/folders/*/*/T/AppTranslocation/*/d/Player_DMG_*.app"
		"/private/var/folders/*/*/T/AppTranslocation/*/d/TimerRush_*.app"
		"/private/var/folders/*/*/T/AppTranslocation/*/d/VidsToGifs_*.app")

echo ""

# Check Primary Directories for Player Files and remove if found
for directory in ${directories[@]}; do
	if [ -d "$directory" ]; then
		echo -e "OSX Shlayer Infection Detected!"
		echo "     $directory"
		if [[ $autoremove == "false" ]]; then
			echo -n "Would you like to delete the malware directory? Enter (y/n): "
			read cleanupChoice
		else
			cleanupChoice="y"
		fi
		if [ $cleanupChoice == "y" ]; then
			sudo rm -rf "$directory" && echo "Malware Has Been Removed..." || echo "unable to remove this directory, please run this script with sudo or manually delete this directory"
		else
			echo "It is recommended to remove this directory to prevent continued infection!"
		fi
		echo ""
	fi
done
