#include <stdio.h>

void
invertAffine(float m[4][4])
{
	float r0[4], r1[4], r2[4], r3[4];

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

    int i;
    for (i = 0; i < 4; i++) {
	    m[0][i] = r0[i];
	    m[1][i] = r1[i];
	    m[2][i] = r2[i];
	    m[3][i] = r3[i];
    }
}

double
factorial(double n)
{
	if (n == 0)
		return 1;
	return n * factorial(n - 1);
}

int
main(int argc, char** argv)
{
	int i;

	for (i = 0; i < 10; i++) {
		double f = factorial(i);
		printf("factorial(%d) = %g\n", i, f);
	}

	float m[4][4] = {
		{ 1,2,3,0 },
		{ 4,5,6,0 },
		{ 7,8,9,0 },
		{ 11,22,33,1 }
	};
	invertAffine(m);
}
