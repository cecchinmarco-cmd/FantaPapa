import assert from "node:assert/strict";
import {resolvePriorityPairs} from "../priority-pairs.mjs";
const order={P:[21,22,23],C:[1,2,3,4,5,6,7,8],D:[11,12],A:[31,32]};
for(const a of ["T","S","-"])for(const b of ["T","S","-"]){const result=resolvePriorityPairs(order,[[4,7]],{4:a,7:b});assert.deepEqual(result.C,a!=="T"&&b==="T"?[1,2,3,7,5,6,4,8]:order.C);}
assert.deepEqual(resolvePriorityPairs(order,[[7,4],[21,23]],{4:"S",7:"T",21:"-",23:"T"}),{...order,C:[1,2,3,7,5,6,4,8],P:[23,22,21]});
assert.deepEqual(resolvePriorityPairs(order,[[4,11]],{11:"T"}),order);
assert.deepEqual(resolvePriorityPairs(order,[],{}),order);
assert.deepEqual(order.C,[1,2,3,4,5,6,7,8]);
console.log("Priority pairs: all tests passed");
