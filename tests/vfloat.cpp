#include <stdio.h>

typedef float v4sf __attribute__((__vector_size__(16)));

struct vec4f
{
    float& operator[](size_t n)
    {
	return ((float*) &vec)[n];
    }
    operator v4sf() const
    {
	return vec;
    }
    v4sf vec;
};

void
invertAffine(vec4f m[4])
{
	vec4f r0, r1, r2, r3;

    // calculate determinant

    // I noticed these terms from determinant are also used below so why do
    // them twice ?? PK
    float d1 = ((m[1][1] * m[2][2]) - (m[1][2] * m[2][1]));
    float d2 = ((m[0][2] * m[2][1]) - (m[0][1] * m[2][2]));
    float d3 = ((m[0][1] * m[1][2]) - (m[0][2] * m[1][1]));
    
    float d = (m[0][0] * d1) + (m[1][0] * d2) + (m[2][0] * d3);
    
#if 0
    const float precisionLimit = 1.0e-10f;
    if (fabsf(d) < precisionLimit) {
        setIdentity(); /* XXX */
        return;
    }
#endif
              
    d = 1.0f / d; // multiplication is cheaper than division
              
    r0[0] = d1 * d;
    r1[0] = (m[2][0] * m[1][2] - m[1][0] * m[2][2]) * d;
    r2[0] = (m[1][0] * m[2][1] - m[2][0] * m[1][1]) * d;

    r0[1] = d2 * d;
    r1[1] = (m[0][0] * m[2][2] - m[2][0] * m[0][2]) * d;
    r2[1] = (m[2][0] * m[0][1] - m[0][0] * m[2][1]) * d;

    r0[2] = d3 * d;
    r1[2] = (m[1][0] * m[0][2] - m[0][0] * m[1][2]) * d;
    r2[2] = (m[0][0] * m[1][1] - m[1][0] * m[0][1]) * d;

    // apply inverse to negated old position
    r3[0] = -((m[3][0] * r0[0]) +
              (m[3][1] * r1[0]) +
              (m[3][2] * r2[0]));
    r3[1] = -((m[3][0] * r0[1]) +
              (m[3][1] * r1[1]) +
              (m[3][2] * r2[1]));
    r3[2] = -((m[3][0] * r0[2]) +
              (m[3][1] * r1[2]) +
              (m[3][2] * r2[2]));

    // clear W terms

    r0[3] = 0;
    r1[3] = 0;
    r2[3] = 0;
    r3[3] = 1.0f;

    m[0] = r0;
    m[1] = r1;
    m[2] = r2;
    m[3] = r3;
}

float sum(vec4f* m, size_t len)
{
    v4sf sum = { 0,0,0,0 };
    for (size_t i = 0; i < len; i++)
	sum += m[i].vec;
    vec4f t;
    t.vec = sum;
    return t[0] + t[1] + t[2] + t[3];
}

int
main(int argc, char** argv)
{
	int i;

	vec4f m[4] = {
		{ 1,2,3,0 },
		{ 3,1,2,0 },
		{ 2,3,1,0 },
		{ 11,22,33,1 }
	};
	invertAffine(m);
	printf("%g\n", sum(m, 4));
}
