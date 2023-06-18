#include <math.h>
#include <cstdint>

#define INLINEYALL static inline __attribute__((always_inline))

#define fmax std::max
#define fmin std::min
#define fabs std::abs

INLINEYALL double clamp(double x, double l, double h) {
    return fmax(l, fmin(h, x));
}

INLINEYALL double isqrt(double y)
{
    double x2 = y * 0.5;
    std::int64_t i = *(std::int64_t *) &y;
    // The magic number is for doubles is from https://cs.uwaterloo.ca/~m32rober/rsqrt.pdf
    i = 0x5fe6eb50c7b537a9 - (i >> 1);
    y = *(double *) &i;
    y = y * (1.5 - (x2 * y * y));   // 1st iteration
    // y  = y * ( 1.5 - ( x2 * y * y ) );   // 2nd iteration, this can be removed
    return y;
}

INLINEYALL double fract(double x) {
    return x - floor(x);
}

typedef struct _vec3 {
    double x;
    double y;
    double z;
} vec3;

typedef struct _vec2 {
    double x;
    double y;
} vec2;

#define VEC3(x,y,z) (vec3){x,y,z}
#define VEC2(x,y) (vec2){x,y}

INLINEYALL vec3 VEC3_add(vec3 x, vec3 y) {
    return VEC3(x.x + y.x, x.y + y.y, x.z + y.z);
}

INLINEYALL vec3 VEC3_abs(vec3 v) {
    return VEC3(fabs(v.x), fabs(v.y), fabs(v.z));
}

INLINEYALL vec3 VEC3_addf(vec3 x, double y) {
    return VEC3(x.x + y, x.y + y, x.z + y);
}

INLINEYALL vec3 VEC3_sub(vec3 x, vec3 y) {
    return VEC3(x.x - y.x, x.y - y.y, x.z - y.z);
}

INLINEYALL vec3 VEC3_subf(vec3 x, double y) {
    return VEC3(x.x - y, x.y - y, x.z - y);
}

INLINEYALL vec3 VEC3_mulf(vec3 x, double y) {
    return VEC3(x.x * y, x.y * y, x.z * y);
}

INLINEYALL double VEC3_length(vec3 v) {
    return sqrt(v.x*v.x + v.y*v.y + v.z*v.z);
}

INLINEYALL vec3 VEC3_fmax(vec3 v, double m) {
    return VEC3(fmax(v.x, m), fmax(v.y, m), fmax(v.z, m));
}

INLINEYALL vec3 VEC3_normalize(vec3 v) {
    return VEC3_mulf(v, isqrt(v.x*v.x + v.y*v.y + v.z*v.z));
}

INLINEYALL double VEC3_dot(vec3 x, vec3 y) {
    return x.x*y.x + x.y*y.y + x.z*y.z;
}

INLINEYALL vec3 VEC3_cross(vec3 a, vec3 b) {
    return VEC3(
        a.y * b.z - a.z * b.y,
        a.z * b.x - a.x * b.z,
        a.x * b.y - a.y * b.x
    );
}

INLINEYALL vec2 VEC2_add(vec2 x, vec2 y) {
    return VEC2(x.x + y.x, x.y + y.y);
}

INLINEYALL vec2 VEC2_addf(vec2 x, double y) {
    return VEC2(x.x + y, x.y + y);
}

INLINEYALL vec2 VEC2_sub(vec2 x, vec2 y) {
    return VEC2(x.x - y.x, x.y - y.y);
}

INLINEYALL vec2 VEC2_subf(vec2 x, double y) {
    return VEC2(x.x - y, x.y - y);
}

INLINEYALL vec2 VEC2_mulf(vec2 x, double y) {
    return VEC2(x.x * y, x.y * y);
}

INLINEYALL double VEC2_dot(vec2 x, vec2 y) {
    return x.x*y.x + x.y*y.y;
}

INLINEYALL double VEC2_length(vec2 v) {
    return sqrt(v.x*v.x + v.y*v.y);
}

INLINEYALL vec2 VEC2_modf(vec2 v, double m) {
    return VEC2(fmod(v.x, m), fmod(v.y, m));
}

typedef struct _mat2 {
    double a11; double a12;
    double a21; double a22;
} mat2;

#define MAT2(a,b,c,d) (mat2){a,b,c,d}

INLINEYALL vec2 MAT2_mulf(mat2 mat, double x, double y) {
    return VEC2(
        mat.a11 * x + mat.a12 * y,
        mat.a21 * x + mat.a22 * y);
}

INLINEYALL mat2 MAT2_rot(double a) {
    double c = cos(a);
    double s = sin(a);
    return MAT2(c, -s, s, c);
}

#define EP .001
#define SCENE_END 10.
#define TRACE_MAX_STEPS 200

#define PI 3.1415

#define FLAGOFF VEC3(1024302.,0.,710212.7)

vec3 playerpos = (vec3){5302.,0.,1190.};
//vec3 playerpos = (vec3){0.,0.,0.};
//vec3 playerpos = FLAGOFF;
vec3 playerrot = (vec3){0.,0.,-1.};

typedef struct _Ray {
    vec3 origin;
    vec3 direction;
} Ray;

typedef struct _Camera {
    vec3 pos;
    vec3 lookat;
    double zoom;
    double fov;
} Camera;

typedef struct _LightBase {
    double colour;
} LightBase;

typedef struct _LightDirectional {
    vec3 direction;
    double colour;
} LightDirectional;

LightBase clightBase = {.6};

LightDirectional clightDirectional = {VEC3(-0.577350,0.577350,-0.577350), .7};

INLINEYALL double noise1d(double co){
    return fract((co * 112.311) * 43758.5453);
}

INLINEYALL double noise2d(double x, double y){
    return fract((x * 12.9898 + y * 78.233) * 43758.5453);
}

INLINEYALL double Primitive_sdRoundBox(vec3 p, vec3 b, double r)
{
    vec3 q = VEC3_sub(VEC3_abs(p), b);
    return VEC3_length(VEC3_fmax(q,0.0)) + fmin(fmax(q.x,fmax(q.y,q.z)),0.0) - r;
}

INLINEYALL double Primitive_sdBoxFrame(vec3 p, vec3 b, double e)
{
    // Inigo Quilez
    p = VEC3_sub(VEC3_abs(p), b);
    vec3 q = VEC3_subf(VEC3_abs(VEC3_addf(p, e)), e);
    return fmin(fmin(
    VEC3_length(VEC3_fmax(VEC3(p.x,q.y,q.z),0.0))+fmin(fmax(p.x,fmax(q.y,q.z)),0.0),
    VEC3_length(VEC3_fmax(VEC3(q.x,p.y,q.z),0.0))+fmin(fmax(q.x,fmax(p.y,q.z)),0.0)),
    VEC3_length(VEC3_fmax(VEC3(q.x,q.y,p.z),0.0))+fmin(fmax(q.x,fmax(q.y,p.z)),0.0));
}

#define SEGW .10
#define SEGR .05
#define SEGP .14
#define DISPW .7
#define DISPH .8
#define DISPD pow(DISPW*DISPW + DISPH*DISPH, 0.5)
INLINEYALL double Object_sdSegmentVer1(vec3 p) {
    
    double d = Primitive_sdRoundBox(p, VEC3(SEGW,DISPH-SEGP,SEGW), SEGR);
    return d;
}

INLINEYALL double Object_sdSegmentHor1(vec3 p) {
    
    double d = Primitive_sdRoundBox(p, VEC3(DISPW-SEGP,SEGW,SEGW), SEGR);
    return d;
}

INLINEYALL double Object_sdSegmentHor2(vec3 p) {
    
    double d = Primitive_sdRoundBox(p, VEC3(DISPW/2.-SEGP/2.,SEGW,SEGW), SEGR);
    return d;
}

INLINEYALL double Object_sdSegmentDiag(vec3 p, double r) {
    
    vec2 _ = MAT2_mulf(MAT2_rot(r), p.x, p.y); p.x = _.x; p.y = _.y;
    double d = Primitive_sdRoundBox(p, VEC3(DISPD/2.+SEGP,SEGW,SEGW), 0.1);
    return d;
}

double Object_sd14Segment(vec3 p, uint16_t ch) {

    p.x += p.y*.2;

    double d = SCENE_END;
    vec3 q; float c;
    
    // Vert
    q = VEC3_add(p, VEC3(-DISPW,-2.*DISPH,0.));
    c = (float)((ch >> 0) & 1);
    d = c * d + (1. - c) * fmin(d, Object_sdSegmentVer1(q));
    
    q = VEC3_add(p, VEC3(0.,-2.*DISPH,0.));
    c = (float)((ch >> 1) & 1);
    d = c * d + (1. - c) * fmin(d, Object_sdSegmentVer1(q));
    
    q = VEC3_add(p, VEC3(DISPW,-2.*DISPH,0.));
    c = (float)((ch >> 2) & 1);
    d = c * d + (1. - c) * fmin(d, Object_sdSegmentVer1(q));
    
    q = VEC3_add(p, VEC3(-DISPW,0.,0.));
    c = (float)((ch >> 3) & 1);
    d = c * d + (1. - c) * fmin(d, Object_sdSegmentVer1(q));
    
    q = VEC3_add(p, VEC3(0.,0.,0.));
    c = (float)((ch >> 4) & 1);
    d = c * d + (1. - c) * fmin(d, Object_sdSegmentVer1(q));
    
    q = VEC3_add(p, VEC3(DISPW,0.,0.));
    c = (float)((ch >> 5) & 1);
    d = c * d + (1. - c) * fmin(d, Object_sdSegmentVer1(q));
    
    // Hor1
    q = VEC3_add(p, VEC3(0.,-3.*DISPH,0.));
    c = (float)((ch >> 6) & 1);
    d = c * d + (1. - c) * fmin(d, Object_sdSegmentHor1(q));
    
    q = VEC3_add(p, VEC3(0.,DISPH,0.));
    c = (float)((ch >> 7) & 1);
    d = c * d + (1. - c) * fmin(d, Object_sdSegmentHor1(q));
    
    // Hor2
    q = VEC3_add(p, VEC3(-DISPW/2.,-DISPH,0.));
    c = (float)((ch >> 8) & 1);
    d = c * d + (1. - c) * fmin(d, Object_sdSegmentHor2(q));
    
    q = VEC3_add(p, VEC3(DISPW/2.,-DISPH,0.));
    c = (float)((ch >> 9) & 1);
    d = c * d + (1. - c) * fmin(d, Object_sdSegmentHor2(q));
    
    // Diag
    static const double r = atan(2.*(DISPH + SEGW + SEGR)/DISPW);
    
    q = VEC3_add(p, VEC3(-DISPW/2.,-2.*DISPH,0.));
    c = (float)((ch >> 10) & 1);
    d = c * d + (1. - c) * fmin(d, Object_sdSegmentDiag(q, -r));
    
    q = VEC3_add(p, VEC3(DISPW/2.,-2.*DISPH,0.));
    c = (float)((ch >> 11) & 1);
    d = c * d + (1. - c) * fmin(d, Object_sdSegmentDiag(q, r));
    
    q = VEC3_add(p, VEC3(-DISPW/2.,0.,0.));
    c = (float)((ch >> 12) & 1);
    d = c * d + (1. - c) * fmin(d, Object_sdSegmentDiag(q, r));
    
    q = VEC3_add(p, VEC3(DISPW/2.,0.,0.));
    c = (float)((ch >> 13) & 1);
    d = c * d + (1. - c) * fmin(d, Object_sdSegmentDiag(q, -r));
    
    return d;
}

INLINEYALL double Object_sdBall(vec3 p)
{
    return Primitive_sdBoxFrame(p, VEC3(.6, .6, .6), .05);
}

INLINEYALL double Scene_sdf_Object(vec3 pos, double vy)
{   
    vec2 _;
    vec3 p = pos;
    p.y += .5;

    double scale = 5.;
    p = VEC3_mulf(p, scale);
    double c = 6.;
    double id_x = floor((p.x - 0.5*c)/c);
    double id_z = floor((p.z - 0.5*c)/c);
    _ = VEC2_subf(VEC2_modf(VEC2_addf(VEC2(p.x, p.z), 0.5*c), c), 0.5*c); p.x = _.x; p.z = _.y;
    
    vec3 _p = p;
    _p.y -= noise2d(id_x, id_z)*vy + 2.;
    double sc = noise2d(id_z, id_x)*3. + .2;
    _p = VEC3_mulf(_p, 1./sc);
    _ = MAT2_mulf(MAT2_rot(noise1d(id_x)), _p.y, _p.z); _p.y = _.x; _p.z = _.y;
    _ = MAT2_mulf(MAT2_rot(noise1d(id_z)), _p.z, _p.x); _p.z = _.x; _p.x = _.y;
    double ball = Object_sdBall(_p)*sc;
       
    return ball/scale;
}

static const uint16_t _TEST= 0b00000000000000;
static const uint16_t _A   = 0b11110010010010;
static const uint16_t _B   = 0b11110000001001;
static const uint16_t _C   = 0b11111100110110;
static const uint16_t _E   = 0b11110000110110;
static const uint16_t _H   = 0b11110011010010;
static const uint16_t _I   = 0b11111100101101;
static const uint16_t _R   = 0b01110010110010;
static const uint16_t _S   = 0b11100100011111;
static const uint16_t _T   = 0b11111110101101;
static const uint16_t _U   = 0b11111101010010;
static const uint16_t _O   = 0b11111100010010;
static const uint16_t _W   = 0b00111111010010;
static const uint16_t _Y   = 0b11001111101111;
static const uint16_t _Z   = 0b10011100111111;
static const uint16_t _0   = 0b01101100010010;
static const uint16_t _3   = 0b11110100011011;
static const uint16_t _4   = 0b11110011011010;
static const uint16_t _LEFT= 0b01011011111111;
static const uint16_t _RIGH= 0b10100111111111;
static const uint16_t _DASH= 0b11110011111111;
static const uint16_t _SCOR= 0b11111101111111;
static const uint16_t str[21] = {
    _S,_E,_E,_LEFT,
        _C,_R,_4,_Z,_Y,_DASH,_W,_I,_T,_H,_DASH,_C,_U,_B,_E,_S,
    _RIGH
};

// Flag: SEE{CR4ZY-WITH-CUBES}
double Scene_sdf_str(vec3 p) {

    double d = SCENE_END;
    double pad = DISPW*2. + SEGP*7.;
    
    double bound = Primitive_sdRoundBox(p, VEC3(pad * 21., 2.*DISPH + 1., SEGW), 0.);
    if (bound > 0.3) return bound;

    for (int j = 0; j < 21; j++) {
        d = fmin(d, Object_sd14Segment(p, str[j])); p.x += pad;
    }
    
    return d;
}

double Scene_sdf(vec3 p)
{
    vec3 p2 = p; p2.x += 2.; p2.z += 2.;
    double object = SCENE_END;
    object = fmin(object, Scene_sdf_Object(VEC3_mulf(p2, 1./7.), 2.)*7.);
    
    double ground = p.y + 2.;
    
    double segment = Scene_sdf_str(VEC3_mulf(VEC3_sub(p, FLAGOFF),1.5))/1.5;;
    
    double sdf = fmin(fmin(object, ground), segment);
    return sdf;
}

vec3 Scene_normal(vec3 p) 
{
    static const double h = 0.01;
    return VEC3_normalize(
        VEC3_add(
            VEC3_add(
                VEC3_mulf(VEC3( 1., -1., -1.), Scene_sdf(VEC3_add(p, VEC3( h, -h, -h)))),
                VEC3_mulf(VEC3(-1., -1.,  1.), Scene_sdf(VEC3_add(p, VEC3(-h, -h,  h))))),
            VEC3_add(
                VEC3_mulf(VEC3(-1.,  1., -1.), Scene_sdf(VEC3_add(p, VEC3(-h,  h, -h)))),
                VEC3_mulf(VEC3( 1.,  1.,  1.), Scene_sdf(VEC3_add(p, VEC3( h,  h,  h)))))
        )
    );
}

double Ray_trace(Ray* ray)
{
    vec3 p = ray->origin;
    vec3 d = ray->direction;
    double dist = 0.;
    
    for (int i = 0; i < TRACE_MAX_STEPS; ++i) {
        vec3 _p = VEC3_add(p, VEC3_mulf(d, dist));
        double _d = Scene_sdf(_p);
        dist += _d;
        if (_d < EP || dist > SCENE_END) break;
    }
    *(&ray->origin) = VEC3_add(p, VEC3_mulf(d, dist));
    return dist;
}

double Ray_lighting(Ray* ray)
{
    double d = Ray_trace(ray);
    //if (d > SCENE_END) return 1.0;
    //if (d < EP) return 0.0;
    double col = 0;
    vec3 normal = Scene_normal(ray->origin);

    if (d < SCENE_END) {
        col += clightBase.colour;
        col += clightDirectional.colour * fmax(0., VEC3_dot(normal, clightDirectional.direction));
    }
    
    // Compute cheap distance fog
    col *= pow(1.4, -d);
    col = clamp(col, 0., 1.);
    
    return col;
}

static const vec3 POS_DEFAULT = VEC3(0., 0., -1.);
static const vec3 LOOKAT_DEFAULT = VEC3(0., 0., 0.);

INLINEYALL void Camera_init(Camera* cam) 
{
    // Move camera to player
    vec3 pos = VEC3_add(playerrot, playerpos);
    vec3 lookat = VEC3_add(LOOKAT_DEFAULT, playerpos);

    *(&cam->pos) = pos;
    *(&cam->lookat) = lookat;
    *(&cam->fov) = 1.;
    *(&cam->zoom) = 1.;
}

vec3 FRONT;
vec3 RIGHT;
vec3 UP;
INLINEYALL void Camera_projectRay(Camera* cam, Ray* ray, vec2 uv)
{
    FRONT = VEC3_normalize(VEC3_sub(cam->lookat, cam->pos));
    vec3 screen_origin = VEC3_add(cam->pos, VEC3_mulf(FRONT, cam->zoom));
    vec3 vert = VEC3(0,1.,0);
    UP = VEC3_normalize(VEC3_sub(vert, VEC3_mulf(FRONT, VEC3_dot(vert, FRONT))));
    RIGHT = VEC3_cross(FRONT, UP);
    
    uv = VEC2_mulf(uv, cam->fov);
    vec3 ro = VEC3_add(VEC3_add(screen_origin, VEC3_mulf(RIGHT, uv.x)), VEC3_mulf(UP, uv.y));
    vec3 rd = VEC3_normalize(VEC3_sub(ro, cam->pos));

    *(&ray->origin) = ro;
    *(&ray->direction) = rd;
}

static Camera cam;
static Ray ray;

double PIXEL_main(double x, double y) {
    x -= .5;
    y -= .5;
    x *= ENV_NX/(float)ENV_NY;
    y = -y;

    //return (x*x + y*y <= playerpos.x*playerpos.x) ? 0.5 : 0.1;
    Camera_init(&cam);
    Camera_projectRay(&cam, &ray, VEC2(x, y));
    return Ray_lighting(&ray);
}
