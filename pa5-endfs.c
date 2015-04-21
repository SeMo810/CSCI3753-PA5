/*
 * Custom encrypted filesystem program using FUSE and xattr.
 * This is for CSCI 3753, Operating Systems, in Spring 2015, Professor Richard Han, Programming Assignment 5.
 * This is adapted from the file fusexmp.c provided with the handout for this project.
 * Author: Sean Moss (semo0788@colorado.edu)
 */

#define FUSE_USE_VERSION 28
#define HAVE_SETXATTR


