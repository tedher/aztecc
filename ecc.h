///////////////////////////////////////////////////////////
// ecc.h
// Elliptic Curve Cryptosystems Header Definition
// Defining class members and methods
// Author  : Tedi Heriyanto
// Edition : 0.0.2.3
// Date    : 13012000
//
// History :
// 10-16-1999 : - changed a4,a6 -> static bigmod *a4,*a6
// 10-30-1999 : - fixed set_point
//              - added assign_zero, assign,get_x,get_y,
//                get_point,sub_point methods 
// 11-04-1999 : added friend functions 
// 11-05-1999 : added bigmod operator==
// 11-12-1999 : added operator <<
// 13-01-2000 : added friend bool
//
// Last revised $ January 20, 2000 $
///////////////////////////////////////////////////////////

#ifndef ECC_H
#define ECC_H

#include "LiDIA/bigmod.h"
	
class point {
private:
	
	static bigmod *a4,*a6;
	
	bigmod x;		// x-coordinate
	bigmod y;		// y-coordinate

	bool is_zero;	// if is_zero == true -> point at infinity
	
public:

	static void init_curve (const bigmod& A4, const bigmod& A6); 
	
	point() 
	{ 
		is_zero=true; 
	}

	point(const bigmod& Xp, const bigmod& Yp)
	{ 
		x = Xp; y = Yp; 
	}

	void set_zero() 
  { is_zero=true;}

	friend void assign(point& H, const point & P)
	{
		H.x = P.x; H.y = P.y;
    H.is_zero = P.is_zero;
	}

	// check if a point is on the elliptic curve
	//friend bool on_curve(const bigmod& x, const bigmod& y);
	void print_curve()
  { 
		cout<<"E = ["<<*a4<<" , "<<*a6<<"]";
  }

  bool on_curve()
	{
		bigmod h;
	  h = (y*y)-(x*x+ *a4)*x-*a6;
	  return (h==0)? 1:0; 
	}

	friend void get_x(bigmod& X, const point& P)
	{   
		X = P.x ;
	}

	friend void get_x(bigint& X, const point& P)
	{   
		X = mantissa(P.x) ;
	}

	friend void get_y(bigmod& Y, const point & P)
	{
		Y = P.y;
	}

	friend void get_y(bigint& Y, const point& P)
	{   
		Y = mantissa(P.y) ;
	}


	void set_point(const bigmod & X, const bigmod & Y)
	{	
		is_zero = false;
		x = X; y = Y;
	}
  
	// --- overloaded operators ---
	friend int operator== (const point& P1, const point& P2);
	friend ostream& operator<< (ostream& c, const point& P);

	//--- elliptic curve arithmatics functions ---

	friend void neg_point (point& H, const point& P);
	friend void add_point (point& H, const point& P1, const point& P2);
	friend void sub_point (point& H, const point& P1, const point& P2);
	friend void mul_point (point& H, const bigint& k, const point& P);
	friend void double_point (point& H, const point& P);
};

#endif

