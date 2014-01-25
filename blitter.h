void fill(uint8_t* fb, int x, int y, int width, int height, uint32_t color) {
  int i,j;
  for(i = 0; i < width; i++) {
    for(j = 0; j < height; j++) {
      fb[(((j+y)*640)+i+x)*4+0] = (color >> 0) & 0xFF;
      fb[(((j+y)*640)+i+x)*4+1] = (color >> 8) & 0xFF;
      fb[(((j+y)*640)+i+x)*4+2] = (color >> 16) & 0xFF;
    }
  }
  return;
}

void drawSymbol(uint8_t* fb, int x, int y, int s, char symbol, uint32_t fg, uint32_t bg) {
  uint8_t* data = font8x8[symbol];
  int i,j;
  for(i = 0; i < 8*s; i++) {
    for(j = 0; j < 8*s; j++) {
      uint32_t color = (data[j/s] & (0x80 >> (i/s)))?fg:bg;
      if ((color >> 24) == 0x00) {
        fb[(((j+y)*640)+i+x)*4+0] = (color >> 0) & 0xFF;
        fb[(((j+y)*640)+i+x)*4+1] = (color >> 8) & 0xFF;
        fb[(((j+y)*640)+i+x)*4+2] = (color >> 16) & 0xFF;
      }
    }
  }
  return;
}

void drawText(uint8_t* fb, int x, int y, int s, const char* text, uint32_t fg, uint32_t bg) {
  int i = 0;
  int j = 0;
  while(*text) {
    if (*text == '\n') {
      i = 0;
      j++;
    } else {
      drawSymbol(fb,x+i*s*8,y+j*s*8,s,*text,fg,bg);
      i++;
    }
    text++;
  }
  return;
}

void drawBoolean(uint8_t* fb, int x, int y, int s, const char* text, const char* t, const char* f, bool b) {
  char buffer[200];
  sprintf(buffer,"%s: %s",text,b?t:f);
  drawText(fb,x,y,s,buffer,b?0x00FF00:0xFF0000,0xFF000000);   
  return;
}
