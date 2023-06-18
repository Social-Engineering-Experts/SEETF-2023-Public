#pragma GCC diagnostic ignored "-Wunused-result"

#include <sys/ioctl.h>
#include <sys/select.h>
#include <signal.h>
#include <algorithm>

#include <stdint.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>

#include <termios.h>
#include <curses.h>

char int2char(uint8_t i) {
    return 48 + i;
}

/* environment stuff */

uint32_t ENV_NX;
uint32_t ENV_NY;

void ENV_console_size(uint32_t* nrows, uint32_t* ncols) {
    struct winsize w;
    ioctl(STDOUT_FILENO, TIOCGWINSZ, &w);
    *nrows = (w.ws_row-1)*2 - 2; // 2 pixels per char
    *ncols = w.ws_col - 1;
}

void ENV_enable_echo() {
    struct termios term;
    tcgetattr(fileno(stdin), &term);
    term.c_lflag |= ECHO;
    tcsetattr(fileno(stdin), 0, &term);
}

void ENV_init_keypress() {
    initscr();
    keypad(stdscr, TRUE);
    noecho();
}

void ENV_init() {
    ENV_console_size(&ENV_NY, &ENV_NX);
    ENV_init_keypress();
}

/* pixelshader stuff */

char* PREV_BUF;
char* PIXEL_BUF;

#include "pixel.h" // Extremely cursed but shutup i dont care

double PIXEL_mainwrapper(double x, double y) {
    if (0 > x || 1 < x) return 0.0;
    if (0 > y || 1 < y) return 0.0;
    return PIXEL_main(x, y);
}

void PIXEL_buffer() {
    char* tmp = PIXEL_BUF;
    PIXEL_BUF = PREV_BUF;
    PREV_BUF = tmp;
    for (uint32_t y = 0; y < ENV_NY; y++) {
        for (uint32_t x = 0; x < ENV_NX; x++) {
            double c = PIXEL_mainwrapper(
                (double)x / (double)ENV_NX,
                (double)y / (double)ENV_NY);
            c = std::max(0., std::min(1., c));
            c *= 255;
            PIXEL_BUF[ENV_NX * y + x] = (uint8_t)(int)c;
        }
    }
}

void PIXEL_init() {
    PIXEL_BUF = (char*)calloc(ENV_NX*ENV_NY, 1);
    PREV_BUF = (char*)calloc(ENV_NX*ENV_NY, 1);
}

/* console stuff */

#define PRINT(X) write(STDOUT_FILENO, X, strlen(X))
#define ANSI_TCOL(R,G,B) "\x1b[38;2;" #R ";" #G ";" #B "m"
#define ANSI_BCOL(R,G,B) "\x1b[48;2;" #R ";" #G ";" #B "m"
#define ANSI_UP(N) "\033[" #N "A"
#define ANSI_DOWN(N) "\033[" #N "B"
#define ANSI_FORW(N) "\033[" #N "C"
#define ANSI_BACK(N) "\033[" #N "D"


const char* BOX = "▄";
const char* NL = "\n";
const char* ANSI_CLEARSCREEN = "\e[1;1H\e[2J";
const char* ANSI_COLRESET = "\033[0m";
const char* ANSI_SAVE_CURSOR = "\033[s";
const char* ANSI_RESTORE_CURSOR = "\033[u";
const char* ANSI_ERASE_LINE = "\033[K";

char ANSI_TCOL_BUF[] = "\x1b[38;2;" "xxx" ";" "xxx" ";" "xxx" "m";
char ANSI_BCOL_BUF[] = "\x1b[48;2;" "xxx" ";" "xxx" ";" "xxx" "m";
char ANSI_UP_BUF[] = "\033[" "xxxx" "A";
char ANSI_DOWN_BUF[] = "\033[" "xxxx" "B";
char ANSI_FORW_BUF[] = "\033[" "xxxx" "C";
char ANSI_BACK_BUF[] = "\033[" "xxxx" "D";

uint16_t CURX = 0;
uint16_t CURY = 0;
uint8_t CURTCOL = 0;
uint8_t CURBCOL = 0;

void CON_clear_screen() {
    PRINT(ANSI_CLEARSCREEN);
    PRINT(ANSI_DOWN(2));
    PRINT(ANSI_SAVE_CURSOR);
}

void _CON_set_coltemplate(char* buf, uint8_t r, uint8_t g, uint8_t b) {
    buf[7] = int2char(r/100);
    buf[8] = int2char((r%100)/10);
    buf[9] = int2char((r%10));
    buf[11] = int2char(g/100);
    buf[12] = int2char((g%100)/10);
    buf[13] = int2char((g%10));
    buf[15] = int2char(b/100);
    buf[16] = int2char((b%100)/10);
    buf[17] = int2char((b%10));
}

void CON_set_TCOL(uint8_t b) {_CON_set_coltemplate(ANSI_TCOL_BUF, 0,b,b); CURTCOL = b;}
void CON_set_BCOL(uint8_t b) {_CON_set_coltemplate(ANSI_BCOL_BUF, 0,b,b); CURBCOL = b;}

void CON_reset_cursor() {
    PRINT(ANSI_RESTORE_CURSOR);
    CURX = 0; CURY = 0;
    CURTCOL = 0; CURBCOL = 0;
}

void CON_reset_color() {
    CON_set_TCOL(0); PRINT(ANSI_TCOL_BUF);
    CON_set_BCOL(0); PRINT(ANSI_BCOL_BUF);
}

void _CON_cursor_template(char* buf, uint16_t n) {
    buf[2] = int2char(n/1000);
    buf[3] = int2char((n%1000)/100);
    buf[4] = int2char((n%100)/10);
    buf[5] = int2char((n%10));
}

void _CON_cursor_UP(uint16_t n) {_CON_cursor_template(ANSI_UP_BUF, n);}
void _CON_cursor_DOWN(uint16_t n) {_CON_cursor_template(ANSI_DOWN_BUF, n);}
void _CON_cursor_FORW(uint16_t n) {_CON_cursor_template(ANSI_FORW_BUF, n);}
void _CON_cursor_BACK(uint16_t n) {_CON_cursor_template(ANSI_BACK_BUF, n);}

void CON_cursor_move(uint16_t x, uint16_t y) {
    int16_t dx = (int16_t)x - (int16_t)CURX;
    int16_t dy = (int16_t)y - (int16_t)CURY;
    CURX = x+1; CURY = y;
    if (dx < 0) {_CON_cursor_BACK(-dx); PRINT(ANSI_BACK_BUF);}
    else if (dx > 0) { _CON_cursor_FORW(dx); PRINT(ANSI_FORW_BUF);}
    if (dy < 0) {_CON_cursor_UP(-dy); PRINT(ANSI_UP_BUF);}
    else if (dy > 0) {_CON_cursor_DOWN(dy); PRINT(ANSI_DOWN_BUF);}
}

void CON_display() {

    CON_reset_cursor();

    // Print stats
    PRINT(ANSI_UP(2));
    PRINT(ANSI_ERASE_LINE);
    printf("Pos: (%.5f, %.5f) ", playerpos.x, playerpos.z);
    //printf("Rot: (%.5f, %.5f)", playerrot.x, playerrot.y);
    printf("\n");
    CON_reset_cursor(); PRINT(ANSI_UP(1)); PRINT(ANSI_ERASE_LINE);
    // DEBUG line 2
    printf("Controls: WASD to move, ARROW KEYS to look around\n");
    CON_reset_cursor(); 
    CON_reset_color();

    // populate buffer
    PIXEL_buffer();
    for (uint32_t _y = 0; _y < ENV_NY >> 1; _y++) {
        for (uint32_t x = 0; x < ENV_NX; x++) {

            uint32_t y = _y << 1;
            uint8_t c1 = PIXEL_BUF[ENV_NX * y + x];
            uint8_t c2 = PIXEL_BUF[ENV_NX * (y+1) + x];

            uint8_t p1 = PREV_BUF[ENV_NX * y + x];
            uint8_t p2 = PREV_BUF[ENV_NX * (y+1) + x];
            if (p1 == c1 && p2 == c2)
                continue;

            CON_cursor_move(x,_y);

            if (CURBCOL != c1) {CON_set_BCOL(c1); PRINT(ANSI_BCOL_BUF);}
            if (CURTCOL != c2) {CON_set_TCOL(c2); PRINT(ANSI_TCOL_BUF);}

            PRINT(BOX);
        }
    }
    PRINT(ANSI_COLRESET);
}

void CON_init() {
    CON_clear_screen();
    CON_set_TCOL(CURTCOL); PRINT(ANSI_TCOL_BUF);
    CON_set_BCOL(CURBCOL); PRINT(ANSI_BCOL_BUF);
    //for (uint32_t _y = 0; _y < ENV_NY / 2; _y++) {
    //    for (uint32_t x = 0; x < ENV_NX; x++) {
    //        PRINT(".");
    //    }
    //    PRINT(NL);
    //}
}

void exiting(int c) {
    CON_clear_screen();
    CON_reset_cursor();
    PRINT(ANSI_COLRESET);
    endwin();
    ENV_enable_echo();
    exit(c);
}

#define WALKSPEED 0.3
int main(int argc, char **argv)
{
    signal(SIGINT, &exiting);
    
    ENV_init();
    CON_init();
    PIXEL_init();

    ungetch('w');

    vec2 _tmp;
    mat2 ROTCAM = MAT2_rot(0.1);
    mat2 ROTCAMINV = MAT2_rot(-0.1);

    while (1) {

        int ch = getch();
        flushinp();
        switch (ch) {

            case 'K':
            case 'k':
            case KEY_BREAK:
            case ERR:
                exiting(0);

            case KEY_UP:
                // _tmp = MAT2_mulf(ROTCAM, playerrot.z, playerrot.y);
                // playerrot.z = _tmp.x; playerrot.y = _tmp.y;
                playerrot = VEC3_normalize(VEC3_add(playerrot, VEC3_mulf(UP, -.1)));
                goto displayscreen;
            case KEY_DOWN:
                //_tmp = MAT2_mulf(ROTCAMINV, playerrot.z, playerrot.y);
                //playerrot.z = _tmp.x; playerrot.y = _tmp.y;
                playerrot = VEC3_normalize(VEC3_add(playerrot, VEC3_mulf(UP, .1)));
                goto displayscreen;
            case KEY_LEFT:
                _tmp = MAT2_mulf(ROTCAMINV, playerrot.x, playerrot.z);
                playerrot.x = _tmp.x; playerrot.z = _tmp.y;
                goto displayscreen;
            case KEY_RIGHT:
                _tmp = MAT2_mulf(ROTCAM, playerrot.x, playerrot.z);
                playerrot.x = _tmp.x; playerrot.z = _tmp.y;
                goto displayscreen;

            // TODO: Replace with actual player controls
            case 'W':
            case 'w':
                playerpos = VEC3_add(playerpos, VEC3_mulf(FRONT, WALKSPEED));
                playerpos.y = 0.;
                goto displayscreen;
            case 'S':
            case 's':
                playerpos = VEC3_add(playerpos, VEC3_mulf(FRONT, -WALKSPEED));
                playerpos.y = 0.;
                goto displayscreen;
            case 'A':
            case 'a':
                playerpos = VEC3_add(playerpos, VEC3_mulf(RIGHT, -WALKSPEED));
                playerpos.y = 0.;
                goto displayscreen;
            case 'D':
            case 'd':
                playerpos = VEC3_add(playerpos, VEC3_mulf(RIGHT, WALKSPEED));
                playerpos.y = 0.;
                goto displayscreen;
            default: break;
        }
        continue;

displayscreen:
        CON_display();
    }
    return 0;  // make sure your main returns int
}