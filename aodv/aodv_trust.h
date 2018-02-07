/*
 * aodv_trust.h
 *
 *  Created on: May 7, 2017
 *      Author: candy-pc
 */

#ifndef AODV_TRUST_H_
#define AODV_TRUST_H_

struct NR{
	int record[6];
	NR *next;
};


struct DT{
	int node;
	float dt;
	//DT *next;
};

struct RT{
	int node;
	float rt;
	RT *next;
};
//通信区域内的节点的间接信任
struct n_IT{
	int count;
	float it;
};
//对不在通信区域内的节点的间接信任
struct IT{
	int node;
	int count;
	float it;
	IT *next;
};

struct T{
	int node;
	float t;
	T *next;
};

#endif /* AODV_TRUST_H_ */
