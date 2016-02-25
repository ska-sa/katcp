#include <stdio.h>
#include <unistd.h>

#include <katpriv.h>
#include <katcp.h>

int config_server_flat_katcp(struct katcp_dispatch *dl, char *configfile, unsigned int port){
  /*host_port in format host:port*/
  int fd;
  struct katcp_flat *f;
  struct katcp_arb *l;

  if(configfile){
    fd = pipe_from_file_katcp(dl, configfile);
    if (fd < 0){
#ifdef DEBUG
      fprintf(stderr, "creation of pipe from file failed\n");
#endif
      return terminate_katcp(dl, KATCP_EXIT_ABORT);
    }
    f = create_flat_katcp(dl, fd, 0, NULL, NULL);
    if (f == NULL){
#ifdef DEBUG
      fprintf(stderr, "unable to create flat data structure\n");
#endif
      close(fd);
      return terminate_katcp(dl, KATCP_EXIT_ABORT);
    }
  }

  if(port){
    l = create_listen_flat_katcp(dl, "arb_listen", port, NULL, NULL);
    if(l == NULL){
#ifdef DEBUG
      fprintf(stderr, "unable to create listener on %u\n", port);
#endif
      return terminate_katcp(dl, KATCP_EXIT_ABORT);
    }
  }

  return 0;
}


int run_server_flat_katcp(struct katcp_dispatch *dl){
  return run_core_loop_katcp(dl);
}
