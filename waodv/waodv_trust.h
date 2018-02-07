/*
 * aodv_trust.h
 *
 *  Created on: May 7, 2017
 *      Author: candy-pc
 */

#ifndef WAODV_TRUST_H_
#define WAODV_TRUST_H_

//邻居节点信任列表
class nr_trust{
public:
	nsaddr_t addr;
	float trust;
	nr_trust * next;
	//


};


#endif /* AODV_TRUST_H_ */
