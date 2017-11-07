# Item catalog project
## Project Description:
A simple web app created with python. Create categories with your favorite items, add, edit or delete items.

### PreRequisites:
- [Python3](https://www.python.org/)
- [Vagrant](https://www.vagrantup.com/)
- [VirtualBox](https://www.virtualbox.org/)

### Getting started:
1. Install python
2. Install Vagrant and VirtualBox

### The virtual machine:

There are a couple of different ways you can download the VM configuration.You can download and unzip this file: [FSND-Virtual-Machine.zip](https://d17h27t6h515a5.cloudfront.net/topher/2017/August/59822701_fsnd-virtual-machine/fsnd-virtual-machine.zip) This will give you a directory called FSND-Virtual-Machine. It may be located inside your Downloads folder. Alternately, you can use Github to fork and clone the repository https://github.com/udacity/fullstack-nanodegree-vm. Either way, you will end up with a new directory containing the VM files. Change to this directory in your terminal with cd. Inside, you will find another directory called vagrant. Change directory to the vagrant directory. From your terminal, inside the vagrant subdirectory, run the command `vagrant up`. This will cause Vagrant to download the Linux operating system and install it. When vagrant up is finished running, you will get your shell prompt back. At this point, you can run `vagrant ssh` to log in to your newly installed Linux VM.

### Run the necessary files:

1. Navigate to the vagrant directory inside the vagrant environment
2. run database_setup.py to create the database
3. run database_init.py to populate the database with items
4. run project.py and navigate to localhost:5000 in your browser