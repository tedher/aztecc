///////////////////////////////////////////////////////////
// ecc.cpp
//
// Elliptic Curve Cryptosystems Functions
// Author : Tedi Heriyanto
//
// History :
//
// Oct 16 : - change initialization -> bigmod *point::a4;
//				  - added timer;  
// Oct 30 : - added mul_point, neg_point, sub_point
// Nov 1  : - fixed mul_point
//          - fixed add_point            
// Nov 4  : - modified some friend functions
//          - fixed mul_point
// Nov 5  : added bigmod operator==
// Nov 7  : fixed init_curve
// Nov 12 : added operator <<
// Jan 13 : added friend bool on_curve
//
// These functions are designed for use in AZTECC 
//
// Version : $0.2.3.$January 13,2000
// For copying/modifying/distributing see license.txt
///////////////////////////////////////////////////////////

#include "ecc.h"

bigmod * point::a4;
bigmod * point::a6;

/////////////////////////////////////////////////////////// 
// Initialize point's equation
//
// Input : A4 and A6
//
// The curve equation's is y^2 = x^3 - a4*x + a6
///////////////////////////////////////////////////////////
void point::init_curve(const bigmod& A4, const bigmod& A6)
{
  point::a4 = new bigmod;
  *point::a4 = A4;
  point::a6 = new bigmod;
  *point::a6 = A6;
}

///////////////////////////////////////////////////////////
// Function : operator ==
//
// Input : P1=(x1,y1) and P2=(x2,y2)
//
// Process : it checks if x1==x2 and y1==y2
//
// Output : 1 if P1=P2
//          0 if P1<>P2
///////////////////////////////////////////////////////////
int operator== (const point& P1, const point& P2)
{

	if((P1.x == P2.x) && (P1.y==P2.y))
		return 1;
	else 
		return 0;
}


///////////////////////////////////////////////////////////
// Function : print the point's coordinate
//            this is just an overloaded operator for <<
//
// Input     : a point
//
// Output    : point coordinate in the form (x,y)
///////////////////////////////////////////////////////////
ostream& operator<< (ostream& c, const point& P)
{
	return c << "("<<P.x<<","<<P.y<<")";
}

///////////////////////////////////////////////////////////
// Function : negate a point
// Input  : P(x,y) in Fp
//
// Process : copy xp to xh
//           inverse yp
//           copy yp to yh
// 
// Output : H(x,-y) in Fp
///////////////////////////////////////////////////////////
void neg_point (point& H, const point& P)
{
	if (P.is_zero)
		H.set_zero();
	else
	{
		H.x = P.x;
		negate(H.y, P.y);
    H.is_zero = false;
	}
}

///////////////////////////////////////////////////////////
// Function : doubling a point
//
// Input   : P=(x,y) in Fp
//
// Process : if P.y <> 0 then
//
//           2P=(x3,y3) where
//            
//           x3=lambda^2 - 2x1 
//           y3=lambda*(x1-x3)-y1
//
//           lambda=((3*x1^2+a4)/(2*y1))   
//
// Output : H(x3,y3)
///////////////////////////////////////////////////////////

void double_point (point& H, const point & P)
{
	bigmod lambda, temp_1, temp_2,A;

	if (P.is_zero || P.y.is_zero())
	{
    H.set_zero();
    return;
	}

	// lambda = (3*(P.x)^2 + P.a4) / 2*(P.y)
	square(temp_1,P.x);
	multiply(temp_2,3,temp_1);
		
	add(temp_1,temp_2,*point::a4);
	//add(temp_1,temp_2,1);
	get_y(temp_2, P);
	temp_2.multiply_by_2();
	divide(lambda,temp_1, temp_2);
		
	// H.x = lambda^2 - 2*(P.x)
	square(temp_1,lambda);
	get_x(temp_2,P);
	temp_2.multiply_by_2();
	subtract(H.x,temp_1,temp_2);
	
	// H.y = lambda*(P.x-H.x)-P.y
	subtract(temp_1,P.x,H.x);
	multiply(temp_2,lambda,temp_1);
	subtract(H.y,temp_2,P.y);

  H.is_zero = false;
}

///////////////////////////////////////////////////////////
// Function : Adding two distinct points
//
// Input   : P1(x1,y1) and P2(x2,y2) in Fp
//
// Process : if P1=point at infinity -> P3 = P2
//           if P2=point at infinity -> P3 = P1
//           if P1=(x1,y1),P2=( x1,y2) or P1=(x1,y1),P2(x2,-y1) -> 
//							point at infinity
//
//					 P1+P2= P3(x3,y3) where
//
//           x3=lambda^2-x1-x2
//           y3=lambda*(x1-x3)-y1  and
//           lambda=(y2-y1)/(x2-x1)
//         
// Output   : H(x3,y3)
///////////////////////////////////////////////////////////

void add_point (point& H, const point & P1, const point & P2)
{
	bigmod lambda,temp_1, temp_2;

	// P1 point at infinity-> H = P2
	if (P1.is_zero)
	{
		assign(H, P2);
		return;
	}
	
	// P2 point at infinity-> H = P1
	if (P2.is_zero)
	{
		assign(H, P1);
		return;
	}
	
	if (!(P1==P2) && P1.y != -P2.y)
	{
		subtract(temp_1, P2.y, P1.y);
		subtract(temp_2, P2.x, P1.x);
		
		divide(lambda,temp_1,temp_2);
		
		square(temp_1,lambda);
		subtract(temp_2,temp_1,P1.x);
		subtract(H.x,temp_2,P2.x);

		subtract(temp_1,P1.x,H.x);
		multiply(temp_2,lambda,temp_1);
		subtract(H.y,temp_2,P1.y);
   
		H.is_zero = false;
	}

  if(P1 == P2)
      double_point(H, P1);
}

///////////////////////////////////////////////////////////
// Function : subtract a point from other point
//
// Input : P(x,y) in Fp
//         Q(x,y) in Fp
//
// Output : H = P - Q 
///////////////////////////////////////////////////////////
void sub_point (point& H, const point & P1, const point & P2)
{
	point Temp;

	//Temp.assign_zero();

	neg_point(Temp, P2);
	add_point(H,P1,Temp);
	H.is_zero=false;
}

///////////////////////////////////////////////////////////
// Function : multiply a point with a big integer
//
// Input : k -> positive big integer
//         P -> an elliptic curve point
//
// Output : H = k.P
// 
// The algorithm used in this function is adapted from :
// * IEEE P1363, Standard Specifications for Public Key Cryptography: 
//   Annex A-Number Theoretic Background, Oct. 1999.
///////////////////////////////////////////////////////////

void mul_point (point& H, const bigint& k, const point & P)
{
	point Q,Temp;
	bigint h,n;
	unsigned long i,t;

	if (k==0)
	{
		H.set_zero();
		return;
	}

	if (k<0)
	{
		Temp.is_zero=false;
		neg_point(Temp,P);
		assign(Q,Temp);
		Q.is_zero=false;
		n=-k;
	}

	else
	{
		assign(Q,P);
		n = k;
	}

	h = 3*n;

	// bit_length return number of bits, but in the standard draft
	// it just need to know the msb index, eg. 8 => (1000)2
	// if I use bit_length => the result will be 4 which is not conform
	// to the standard msb index = 3, because it's start counting from 0.
	// The difference is 1, so we just need to subtract the bit_length by 1.
	t=h.bit_length()-1; 
		
	for(i=t-1;i>0;i--)
	{
		double_point(Temp,Q);
		assign(Q,Temp);

		if (h.bit(i)==1 && k.bit(i)==0)
			add_point(Q,Temp,P);
		if (h.bit(i)==0 && k.bit(i)==1)
			sub_point(Q,Temp,P);
	} // for

	assign(H,Q);
	H.is_zero=false;
}
