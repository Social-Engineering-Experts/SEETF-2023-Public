#define EP .0001
#define SCENE_END 10.
#define TRACE_MAX_STEPS 200

#define PI 3.1415
#define sTime iTime*.1

#define FLAGOFF vec3(10210.,0.,42912.)

struct Ray {
    vec3 origin;
    vec3 direction;
};

struct Camera {
    vec3 pos;
    vec3 lookat;
    float zoom;
    float fov;
};

struct LightBase {
    float colour;
};

struct LightDirectional {
    vec3 direction;
    float colour;
};

LightBase clightBase = LightBase(.6);

LightDirectional clightDirectional = \
    LightDirectional(normalize(vec3(1.)), .7);
    
float noise(in float a) {
    float x = 10298.*sin(12032.*a + 982302.);
    return x - floor(x);
}

mat2 rot(in float a) {
    float c = cos(a);
    float s = sign(2.-mod(a,4.)) * sqrt(1.-c*c);
    return mat2(c, -s, s, c);
}


float Primitive_sdRoundBox( vec3 p, vec3 b, float r )
{
  vec3 q = abs(p) - b;
  return length(max(q,0.0)) + min(max(q.x,max(q.y,q.z)),0.0) - r;
}

float Primitive_sdBoxFrame(vec3 p, vec3 b, float e)
{
    // Inigo Quilez
    p = abs(p)-b;
    vec3 q = abs(p+e)-e;
    return min(min(
    length(max(vec3(p.x,q.y,q.z),0.0))+min(max(p.x,max(q.y,q.z)),0.0),
    length(max(vec3(q.x,p.y,q.z),0.0))+min(max(q.x,max(p.y,q.z)),0.0)),
    length(max(vec3(q.x,q.y,p.z),0.0))+min(max(q.x,max(q.y,p.z)),0.0));
}

#define SEGW .10
#define SEGR .05
#define SEGP .14
#define DISPW .7
#define DISPH .8
#define DISPD pow(DISPW*DISPW + DISPH*DISPH, 0.5)
float Object_sdSegmentVer1(in vec3 p) {
    
    float d = Primitive_sdRoundBox(p, vec3(SEGW,DISPH-SEGP,SEGW), SEGR);
    return d;
}

float Object_sdSegmentHor1(in vec3 p) {
    
    float d = Primitive_sdRoundBox(p, vec3(DISPW-SEGP,SEGW,SEGW), SEGR);
    return d;
}

float Object_sdSegmentHor2(in vec3 p) {
    
    float d = Primitive_sdRoundBox(p, vec3(DISPW/2.-SEGP/2.,SEGW,SEGW), SEGR);
    return d;
}

float Object_sdSegmentDiag(in vec3 p, float r) {
    
    p.xy *= rot(r);
    float d = Primitive_sdRoundBox(p, vec3(DISPD/2.+SEGP,SEGW,SEGW), 0.1);
    return d;
}

float Object_sd14Segment(in vec3 p, bool[14] char) {

    p.x += p.y*.2;

    float d = SCENE_END;
    vec3 q;
    
    // Vert
    q = p + vec3(-DISPW,-2.*DISPH,0.);
    d = char[0] ? d : min(d, Object_sdSegmentVer1(q));
    
    q = p + vec3(0.,-2.*DISPH,0.);
    d = char[1] ? d : min(d, Object_sdSegmentVer1(q));
    
    q = p + vec3(DISPW,-2.*DISPH,0.);
    d = char[2] ? d : min(d, Object_sdSegmentVer1(q));
    
    q = p + vec3(-DISPW,0.,0.);
    d = char[3] ? d : min(d, Object_sdSegmentVer1(q));
    
    q = p + vec3(0.,0.,0.);
    d = char[4] ? d : min(d, Object_sdSegmentVer1(q));
    
    q = p + vec3(DISPW,0.,0.);
    d = char[5] ? d : min(d, Object_sdSegmentVer1(q));
    
    // Hor1
    q = p + vec3(0.,-3.*DISPH,0.);
    d = char[6] ? d : min(d, Object_sdSegmentHor1(q));
    
    q = p + vec3(0.,DISPH,0.);
    d = char[7] ? d : min(d, Object_sdSegmentHor1(q));
    
    // Hor2
    q = p + vec3(-DISPW/2.,-DISPH,0.);
    d = char[8] ? d : min(d, Object_sdSegmentHor2(q));
    
    q = p + vec3(DISPW/2.,-DISPH,0.);
    d = char[9] ? d : min(d, Object_sdSegmentHor2(q));
    
    // Diag
    float r = atan(2.*(DISPH + SEGW + SEGR)/DISPW);
    
    q = p + vec3(-DISPW/2.,-2.*DISPH,0.);
    d = char[10] ? d : min(d, Object_sdSegmentDiag(q, -r));
    
    q = p + vec3(DISPW/2.,-2.*DISPH,0.);
    d = char[11] ? d : min(d, Object_sdSegmentDiag(q, r));
    
    q = p + vec3(-DISPW/2.,0.,0.);
    d = char[12] ? d : min(d, Object_sdSegmentDiag(q, r));
    
    q = p + vec3(DISPW/2.,0.,0.);
    d = char[13] ? d : min(d, Object_sdSegmentDiag(q, -r));
    
    return d/2.;
}

float Object_sdBall(in vec3 p)
{
    float d = Primitive_sdBoxFrame(p, vec3(.6), .05);
    return d;
}

float Scene_sdf_Object(in vec3 pos, float vy)
{   
    vec3 p = pos;
    p.y += .5;

    float scale = 3.;
    p = p*scale;
    float c = 6.;
    float id_x = floor((p.x - 0.5*c)/c);
    float id_z = floor((p.z - 0.5*c)/c);
    p.xz = mod(p.xz+0.5*c,c)-0.5*c;
    
    vec3 _p = p;
    _p.y -= noise(id_x * id_z)*vy;
    float sc = noise(id_x * id_z * 3.) + .2;
    _p /= sc;
    _p.yz *= rot(noise(id_x)); _p.zx *= rot(noise(id_z));
    float ball = Object_sdBall(_p)*sc;
       
    return ball/scale * 0.6;
}

float Scene_sdf_Ground(in vec3 p)
{   
    float ground = p.y + 1.1;
    return ground;
}

#define T true
#define F false
bool _TEST[14]= bool[14](F,F,F, F,F,F, F,F, F,F, F,F,F,F);

bool _A[14]   = bool[14](F,T,F, F,T,F, F,T, F,F, T,T,T,T);
bool _B[14]   = bool[14](T,F,F, T,F,F, F,F, F,F, T,T,T,T);
bool _C[14]   = bool[14](F,T,T, F,T,T, F,F, T,T, T,T,T,T);
bool _E[14]   = bool[14](F,T,T, F,T,T, F,F, F,F, T,T,T,T);
bool _H[14]   = bool[14](F,T,F, F,T,F, T,T, F,F, T,T,T,T);
bool _I[14]   = bool[14](T,F,T, T,F,T, F,F, T,T, T,T,T,T);
bool _R[14]   = bool[14](F,T,F, F,T,T, F,T, F,F, T,T,T,F);
bool _S[14]   = bool[14](T,T,T, T,T,F, F,F, T,F, F,T,T,T);
bool _T[14]   = bool[14](T,F,T, T,F,T, F,T, T,T, T,T,T,T);
bool _U[14]   = bool[14](F,T,F, F,T,F, T,F, T,T, T,T,T,T);
bool _O[14]   = bool[14](F,T,F, F,T,F, F,F, T,T, T,T,T,T);
bool _W[14]   = bool[14](F,T,F, F,T,F, T,T, T,T, T,T,F,F);
bool _Y[14]   = bool[14](T,T,T, T,F,T, T,T, T,T, F,F,T,T);
bool _Z[14]   = bool[14](T,T,T, T,T,T, F,F, T,T, T,F,F,T);

bool _0[14]   = bool[14](F,T,F, F,T,F, F,F, T,T, F,T,T,F);
bool _3[14]   = bool[14](T,T,F, T,T,F, F,F, T,F, T,T,T,T);
bool _4[14]   = bool[14](F,T,F, T,T,F, T,T, F,F, T,T,T,T);
bool _LEFT[14]= bool[14](T,T,T, T,T,T, T,T, F,T, T,F,T,F);
bool _RIGH[14]= bool[14](T,T,T, T,T,T, T,T, T,F, F,T,F,T);
bool _DASH[14]= bool[14](T,T,T, T,T,T, T,T, F,F, T,T,T,T);
bool _SCOR[14]= bool[14](T,T,T, T,T,T, T,F, T,T, T,T,T,T);

#define _(C) d = min(d, Object_sd14Segment(p, C));   p.x += pad;

// Flag: SEE{CR4ZY-WITH-CUBES}
float Scene_sdf_str(in vec3 p) {

    float d = SCENE_END;
    float pad = DISPW*2. + SEGP*7.;
    
    float bound = Primitive_sdRoundBox(p, vec3(pad * 21., 2.*DISPH + 1., SEGW), 0.);
    if (bound > 0.3) return bound;
    
    _(_S)_(_E)_(_E)_(_LEFT)
        _(_C)_(_R)_(_4)_(_Z)_(_Y)_(_DASH)_(_W)_(_I)_(_T)_(_H)_(_DASH)_(_C)_(_U)_(_B)_(_E)_(_S)
    _(_RIGH)
    
    return d;
}

float Scene_sdf(in vec3 p)
{
    vec3 p1 = p; p1.xz += 1.;
    vec3 p2 = p; p1.xz += 2.;
    vec3 p3 = p; p3.xz += 4.;
    float object = Scene_sdf_Object(p, 2.);
    object = min(object, Scene_sdf_Object(p1/2., 2.)*2.);
    object = min(object, Scene_sdf_Object(p2/4., 4.)*4.);
    object = min(object, Scene_sdf_Object(p3/16., 4.)*16.);
    
    float ground = Scene_sdf_Ground(p);
    
    float segment = Scene_sdf_str((p - FLAGOFF)*1.5)/1.5;
    
    float sdf = min(min(object, ground), segment);
    return sdf;
}

vec3 Scene_normal(in vec3 p) 
{
    const float h = EP;
    const vec2 k = vec2(1,-1);
    return normalize( k.xyy*Scene_sdf( p + k.xyy*h ) + 
                      k.yyx*Scene_sdf( p + k.yyx*h ) + 
                      k.yxy*Scene_sdf( p + k.yxy*h ) + 
                      k.xxx*Scene_sdf( p + k.xxx*h ) );
}

float Ray_trace(inout Ray ray)
{
    vec3 p = ray.origin;
    vec3 d = ray.direction;
    float dist = 0.;
    
    for (int i = 0; i < TRACE_MAX_STEPS; ++i) {
        vec3 _p = p + dist*d;
        float _d = Scene_sdf(_p);
        dist += _d;
        if (_d < EP || dist > SCENE_END) break;
    }
    ray.origin = p + dist*d;
   
    return dist;
}

vec3 Ray_lighting(in Ray ray)
{
    float d = Ray_trace(ray);
    vec3 col = vec3(0);
    vec3 normal = Scene_normal(ray.origin);

    col += clightBase.colour;
    col += clightDirectional.colour * clamp(dot(normal, clightDirectional.direction), 0., 1.);
    
    // Compute cheap distance fog
    col *= pow(2., -d);
    col = clamp(col, 0., 1.);
    
    return col;
}

void Camera_init(inout Camera cam) 
{
    vec3 off = vec3(-iTime, 0., -.5); //+ FLAGOFF;
    cam.pos = vec3(0., -1., -1.) + off;
    cam.lookat = vec3(0., 0., 0.) + off;
    cam.zoom = 1.;
    cam.fov = 1.;
}

void Camera_mouse(inout Camera cam)
{
    vec2 m = (iMouse.xy / iResolution.xy -.5 )* 2.;
    cam.pos.xz = (cam.pos.xz - cam.lookat.xz) * rot(m.x) + cam.lookat.xz;
    cam.pos.zy = (cam.pos.zy - cam.lookat.zy) * rot(m.y) + cam.lookat.zy;
    cam.pos.y = max(cam.pos.y, -1.);
}

Ray Camera_projectRay(in Camera cam, in vec2 uv)
{
    vec3 front = normalize(cam.lookat - cam.pos);
    vec3 screen_origin = cam.pos + front * cam.zoom;
    vec3 vert = vec3(0,1.,0);
    vec3 up = normalize(vert-front*dot(vert, front));
    vec3 right = cross(front, up);
    
    uv *= cam.fov;
    vec3 ro = screen_origin + uv.x * right + uv.y * up;
    vec3 rd = normalize(ro - cam.pos);
    return Ray(ro, rd);
}

void mainImage(out vec4 fragColor, in vec2 fragCoord)
{
    vec2 uv = fragCoord/iResolution.xy - .5;
    uv.x *= iResolution.x/iResolution.y;
    
    Camera cam; Camera_init(cam);
    Camera_mouse(cam);
    Ray ray = Camera_projectRay(cam, uv);
    
    vec3 col = Ray_lighting(ray);
    
    fragColor = vec4(col, 1.);
}