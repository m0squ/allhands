### A Makefile about difficult Git stuff... ###

### The relative path for all of the commands executed in this Makefile is the WORKING DIRECTORY ###

### Get started by calling the following functions with the required arguments ###
#   $ git init
#   $ make identify
#   $ git add
#   $ make commit
#   $ make connect
#   $ make push

### Useful Git commands ###
#   $ git add    | Add files to commit
#   $ git init   | Make the directory a Git repository
#   $ git status | Show the committed, modified and untracked files in the directory

# make config email="user@website.com" name="user": configures your Git profile. This is required for you to commit your work
config:
	git config --global user.email "$(email)"
	git config --global user.name "$(name)"

# make connect url="https://github.com/user/repo.git"           : connects the external repository to the Git one
#              url="https://user:token@github.com/user/repo.git": this also sets the user and the token to use when updating the external repository
connect:
	git remote add origin $(url)
	git branch -M master

# make disconnect: disconnects the external repository from the Git repository
disconnect:
	git remote rm origin

# make update: updates modified files on the Git repository
update:
	git add -u
# make rm file="file.txt": removes a file from the Git repository
rm:
	git rm $(file) --cached

# make commit msg="Commit\ message": updates the Git repository
commit:
	git commit -m $(msg)

# make push: updates the external repository
push:
	git push -u origin master
