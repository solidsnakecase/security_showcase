# DSA Deep Dive

***This is a mess of notes that was originally from an online source. It's very unorganized but worth a read if you learn best visually and have incredibly limited time.  It may not help you in the interview, but it will help you with a deeper understanding of DSA.***

## Data Structures Deep Dive
### Strings
#### StringBuilder 
A StringBuilder in Java is a mutable sequence of characters. Similar to StringBuffer except it differs in terms of synchronization. The StringBuilder class has no guarantee of synchronization whereas the StringBuffer class does. Therefore this class is designed for use as a drop-in replacement for StringBuffer in places where the StringBuffer was being used by a single thread (as is generally the case). Where possible, it is recommended that this class be used in preference to StringBuffer as it will be faster under most implementations. Instances of StringBuilder are not safe for use by multiple threads. If such synchronization is required then it is recommended that StringBuffer be used.

StringBuilder append(X x) - method appends the string representation of the X type argument to the sequence.
Why concatenation is slower than String Buffer (concatenation requires an additional append operations.
Amortized time complexity: 
https://yourbasic.org/algorithms/amortized-time-complexity-analysis/
+ vs. String Builder (And when to concatenate) 
💡
For simple concatenation, you don’t need to use StringBuilder as the Java compiler will do the trick for you. Although, if you need to concatenate inside a loop, you need to manually apply StringBuilder.  If you use simple concatenation the JVM will instantiate a new StringBuilder for each iteration, causing severe performance degradations. StringBuilder has a notable start up cost. 
More about the tradeoffs with both: https://dzone.com/articles/string-concatenation-performacne-improvement-in-ja

Strings are immutable, meaning that any change to the data results in a new copy of the string being created. This can have a performance impact with large strings. 

String cheat sheet: https://stackoverflow.com/questions/53214160/java-best-practices-on-string-concatenation-and-variable-substituittion-in-stri

### Arrays
A 2D array is an array of references to arrays. So if you assign returnArray[i] = state[i], you are simple making returnArray[i] refer to the same array that state[i] refers to. Thus, modifying returnArray[i][j] will modify the j’th element of whatever state[i] was.



Iterating over 2D arrays 


Remember that column lengths can differ per row as a 2D array, is an an array with reference to arrays. 

One way to create a 2D Array


Remember:  array[row][column]
Sorting a 2d Array
Arrays.sort(arr, Comparator.comparingDouble(a -> a[0]));

https://stackoverflow.com/questions/15452429/java-arrays-sort-2d-array
Hash Table & Hash Map
A hash table is a data structure that implements an associative array. You give it a key and associate a value with it for very quick lookups. Hash Tables have constant lookup times. 

The key and the value of a hash table can be any data structure. 


A hash function takes in a string, converts that into an index. Then we can find the value we're looking for. The array is often much smaller than the number of hash codes. The reason we remap the hashcode (number) into an index (a smaller number) is because we want to use smaller numbers for the index in the event we have large key sizes (that may not be usable as indexes in an array). 

### Collisions
Two strings could have the same hash code. There are an infinite number of strings but a finite number of hash codes. Additionally, since we are remapping a hash code into an even smaller index, two things with different hash codes could be mapped to the same index. This is called a collision and there are a few ways of handling collisions. 

#### Chaining (Closed addressing) 

One of the most common solutions to handle collisions is “chaining”. When there are collisions, the collisions get stored in a linked list. Let’s say we had a hash table that had strings (names of people) for keys that corresponded to info about the person (people objects). We use an array of a linked list of people (since all the people involved in the collision, which in the picture below is Christy, Kevin and Alex is now in the linked list).  
The linked list contains the person objects and the keys as well. We need the key so we know what person object to get. If we didn’t we would see all these people that map to the same index but we wouldn’t know which one they are. When there is a collision we would have to go through each node in the linked list till we find what we are looking for. If we are insert a key pair into the hash table and the key already exists in the table, we update the value. Here we still have all items in the same place (unlike in linear probing) so the lookup is quicker. 

Using a Linked List can come at a cost. If the load factor is low, it might be more efficient to use open addressing. 

#### Open Addressing 

Open addressing is a method of handling collisions by placing an item somewhere, other than its calculated address. We need to do this to avoid mapping something to an index which is already occupied by something else. It’s called open addressing because every location is open to any item. 

Open addressing can use a variety of techniques to decide where to place an item that doesn’t go where it should. Linear probing is an open addressing technique, where if a calculated address is occupied then a linear search is used to find the next available slot. If linear probing gets to the end of the array and it still can’t find a free space it might cycle back from the beginning of the array and continue searching from there. The “might” is because in the event that a key is calculated to have an index of 0 (which is the beginning of an array) and if there were no free space when we used linear probing. After getting to the end, there would be no need to cycle back as we have iterated through the entire array. 


The more items you insert into a hash table, the more likely you are to get collisions when you insert data. One way to get around this is to make the hash table bigger than the size of data you're expecting. Perhaps so that only 70% of the hash table is ever occupied. The ratio of the number of items stored and the size of the data array is called the load factor.

load factor = number of items / size of array

If the hash table is implemented as a resizable (dynamic) data structure, it could be made to resize automatically when the load factor reaches a certain threshold. As long as the load factor is relatively low, open addressing with linear probing should work reasonably well. 

Linear probing can result in “primary clustering”, where keys might cluster together in the array while large proportions of it remain unoccupied. 

Rather than scanning along one by one Plus 3 rehash looks every 3 spaces until a free space is found. This helps avoid primary clustering. 

Quadratic probing will square the number of failed attempts when deciding how long from the point of the original collision to look next. Each time another failed attempt is made, the distance from the original point of collision grows rapidly. 


Double hashing applies a second hash function to the key when a collision occurs. The result of the second hash function gives the number of positions along from the point of the original collision to try next.  

In a well-dimensioned hash table, the average cost (number of instructions) for each lookup is independent of the number of elements stored in the table. Many hash tables allow insertions and deletions at a constant average cost per operation. 

### Hashing 

bit field - a series of bits. It’s used to determine what data you have and what data you don’t. 

mask (bitmask) - data used for bitwise operations particularly in a bit field. 

masking - refers to the process of using a mask for bit wise operations 

As shown below when masking bits to 1: 

Fun fact: Dictionaries in Python are the implementation of hash tables. 

Hash tables turn out to be on average more efficient than search trees or any other table lookup structure. For this reason, they are widely used in many kinds of computer software, particularly for associative arrays, database indexing, caches, and sets.

Time Complexity 
We generally assume we have  a good hash table so we have constant time for inserts, deletions and searching. In the real world we make sure we have a good hash table. 


Things to do with Hash Tables: 
Read about collision handling
Read how hash tables grow/shrink 
Implement a simple hash table 
Practice questions 

#### More about hashing: 
hash function - any function that can be used to map a data set of an arbitrary size to a data set of a fixed size, which falls into the hash table.

If you know all the keys in advance, it’s possible to come up with a perfect hash function. One that will produce a unique index for every item. 

To summarize the types of collision resolution: 

#### Things hash function should do: 
Minimize collisions 
Uniform distribution of hash values 
Easy to calculate
Resolve any collisions 

#### Resizing the hash table

The size of the hash table can be increased in order to spread the hash entries further apart. A threshold value signifies the percentage of the hash table that needs to be occupied before resizing. A hash table with a threshold of 0.6 would resize when 60% of the space is occupied. As a convention, the size of the hashtable is doubled. This can be memory intensive. In practice when resizing, a hash table’s old size is doubled and then rounded to the nearest prime number to get the size of the new hash table. 

With the growth of a hash table's load factor, the number of collisions increases, which leads to the decrease of the tables’s overall performance. It is bearable for hash tables with chaining, but unacceptable for hash tables based on open addressing due to essential performance drop. The solution is to resize table, when its load factor exceeds given threshold.

As well, when table becomes too rare, it's reasonable to pack the array in order to save space.

When resizing, the entries will need to be rehashed since the index was calculated using the array’s size. This will require iterating over the old hash table and adding each entry to the new hash table. This takes O(n) time. Dynamic size hash tables are inappropriate for real-time applications (consider that rehashing all the values and calculating the new array size (involves doubling the old size and rounding to the nearest prime (rounding to the nearest prime can a bit of time)) takes a considerable amount of time). 

There are two situations we need resizing. When a hash table is filled too tight (loadFactor > thresholdMax) or it is filled too rare (loadFactor < thresholdMin).

Java’s Hash Map has a threshold of .75 (75%) and uses quadratic probing. 

C++ uses chaining (closed addressing) for hash tables. 

To summarize everything: 
### Hash Map vs Hash Table

This is a frequently asked interview question. HashMap and Hashtable both implement the java.util Map interface but there's a difference between them. 



About hash table (simple explanation): https://www.educative.io/edpresso/what-is-a-hash-table
Gayle’s video about hash tables: https://www.youtube.com/watch?v=shs0KM3wKv8
Excellent video on hash tables: https://www.youtube.com/watch?v=KyUTuwz_b7Q
About hash tables: https://www.hackerearth.com/practice/data-structures/hash-tables/basics-of-hash-tables/tutorial/
About hash table resizing: http://www.algolist.net/Data_structures/Hash_table/Dynamic_resizing
Hap Map vs Hash Table (Java): https://beginnersbook.com/2014/06/difference-between-hashmap-and-hashtable/
HashSet 
The HashSet class implements the Set interface, backed by a HashMap instance. There’s no guarantee of the constant order of elements over time. This class permits the null element. The class also offers constant time performance for the basic operations like add, remove, contains, and size. 



It’s important to note that a hash table is slower than a hash map. 

About HashSet: https://www.geeksforgeeks.org/hashset-in-java/

The threshold load factor of a hash set is .75 just like a hash map. 

Hash Sets are not synchronized. 
LinkedHashMap 
A linked hash map is exactly like a hash map expect that it maintains insertion order. It implements Map<K, V> interface, and extends HashMap<K, V> class. 


#### LinkedHashSet
A linked hash set is exactly like a hash set, except it maintains insertion order. Just like a linked hash map, internally its implemented as a doubly linked list. 
Linked List 
A linked list is a data structure that is a series of connected nodes. Each nodes stores data and has the address of the next node.  


Head = first node (where we start from in a linked list)
The last node can be identified because it’s “next” points to NULL. Each node in the linked list tells us where the next node is. 

Each node of a Linked List consists of;

A data item
An address of another node

How we would insert a node into a linked list


So in summary :

NewNode.next -> RightNode;
LeftNode.next -> NewNode;

Doing something similar to what’s above in an array would’ve required shifting around elements. 

Review of Static Classes: https://www.geeksforgeeks.org/static-class-in-java/

### Linked Lists

About Linked Lists (This website is an amazing resource for learning data structures and algorithms): https://www.programiz.com/dsa/linked-list

A Simple Singly Linked List Implementation (shows how to create a LinkedList with a tail pointer): https://www.javatpoint.com/java-program-to-create-and-display-a-singly-linked-list

#### Linked List Applications

Dynamic memory allocation 
Implemented in stack and queue
In undo functionality of software 
Hash Tables, Graphs

Head = first node 
Tail = last node 

Usually when we delete a node we take in the previous node (the node before the node we want to delete). Then we set that previous node’s next pointer to point to the node after the next node so: previousNode.next = previousNode.next.next;

There’s a leetcode problem when we are only given the node we want to delete. In which case we take the next node’s value and next value and then set it those attributes to the node we want to delete. So we’d do something like this: 

public void deleteNode (Node node) {
    node.val = node.next.val;
    node.next = node.next.next;
}
Traversing a linked list: 
To print elements we use a temp node, which is the head and we keep looping in a while loop until the temp node is null. 

while (temp != null) {
    System.out.println(temp.value);
    temp = temp.next;
}

Notice how we don’t loop by doing temp.next != null as if we did we’d print all node values except the last node because node.next of the last node is null, which causes us to jump out of the while loop instead of printing the last nodes value. 

To get the last node of the linked list: 
Instead of you traversing in a while loop using temp != null we would traverse the linked list till we get to the last node and then break out of the loop before running it for the last node (so temp would be the last node). 

while (temp.next != null) {
    temp = temp.next;
}
Types of Linked List 
Singly Linked List 
Doubly Linked List 
Circular Linked List 

#### Doubly Linked List
A doubly linked list is a linked list where each node has an additional pinter to a previous node. This means we can go forwards or backwards. 

struct node {
    int data;
    struct node *next;
    struct node *prev;
}

A circular linked list is a variation in which the last element is linked to (points to) the first element. This forms a circular loop. 


A singly linked list can be singly or doubly linked. 

For a singly linked list, the next pinter of the last item points to the first item. 

In a doubly linked list, the  previous point of the first item points to the last item as well. 

There is a cycle in a linked list if there is some node in the list that can be reached again by continuously following the next pointer.

### ArrayList
An array list in Java is implemented as a resizable array. 
Time Complexity of ArrayList operations
 add() – takes O(1) time
 add(index, element) – in average runs in O(n) time
 get() – is always a constant time O(1) operation
 remove() – runs in linear O(n) time. We have to iterate the entire array to find the element qualifying for removal. To remove by index, ArrayList find that index using random access in O(1) complexity, but after removing the element, shifting the rest of the elements causes overall O(N) time complexity. Can be O(1) if removing from the beginning of the list or a list with only one element. 
indexOf() – also runs in linear time. It iterates through the internal array and checking each element one by one. So the time complexity for this operation always requires O(n) time
contains() – implementation is based on indexOf(). So it will also run in O(n) time


Be careful when iterating and remove elements in the array. See below. 

### Stack
A stack is a data structure that lets you put items into them and take them out like a stack of plates (so in a LIFO (last in first out) order). 

push - add an element to the top of a stack 
pop - remove element from the top of the stack and return it
isEmpty - check if the stack is empty 
isFull - check if the stack is full 
peek - get the value of the top element without removing it

A stack uses a pointer “top”, which keeps track of the index of the top of the element in the array. Btw a stack is typically implemented as an array but it can also be implemented as a list. Top is initialized to -1 when creating a stack. This lets us know that the stack is empty. The pointer top is decremented (during a pop) or incremented (during a push). 

Before popping we check if the stack is empty and before pushing, we check if the stack is full. 

The pop and push operations of a stack are done in constant time. 

### Queue 
A queue follows the first in first out (FIFO) rule - the item that goes in is the item that comes out first too. 

Basic Operations of a Queue 
enqueue - add an element to the end of the queue
dequeue - remove an element from the front of the queue
isEmpty - check if the queue is empty
isFull - check if the queue is full
peek - get the value of the front of the queue without removing it
Working of Queue 
two pointers: front and rear 
front tracks the first element of the queue 
rear tracks the last element of the queue
initially, set the value of front and rear to -1

#### Enqueue Operation 
check if the queue is full 
for the first element set front to 0
increase the rear index by 1
add the new element in the position pointed to by rear

#### Dequeue Operation 
check if the queue is empty 
return the value pointed to by front 
increase the front index by 1 
for the last element, reset the values of front and rear to -1 

#### Limitation of Queue 

As you can see below, after a bit of enqueuing and dequeuing, the size of the queue gets reduced. 


 The indexes 0 and 1 can only be used after the queue is reset when all the elements have been dequeued.

After REAR reaches the last index, if we can store extra elements in the empty spaces (0 and 1), we can make use of the empty spaces. This is implemented by a modified queue called the circular queue.

Time Complexity: The complexity of enqueue and dequeue operations in a queue using an array is O(1). 

#### Applications of Queue Data Structure
CPU Scheduling, Disk Scheduling
When data is transferred asynchronously between two processes. The queue is used for synchronization. eg. IO Buffers, pipes, file IO, etc
Call center phone systems use queues to hold people calling them in order 

Resources: 

About Queues: https://www.programiz.com/dsa/queue

#### Types of Queues

##### Simple Queue - insertion only takes place at the rear and removal only at the front. It strictly follows FIFO rule. The queue we discussed earlier was a simple queue. 

##### Circular Queue - the last element points to the first element making a circular link
The main advantage is better memory utilization. If the last position is full and the first position is empty then an element can be inserted in the first position. This action isn't possible in a simple queue. 

The operations are identical to the simple queue except for a few differences. We circularly increase front and rear by one in dequeue and enqueue respectively. 

When checking for when the queue is full, there's now an additional case: 

Case 1: front = 0 && rear = size - 1
Case 2: front = rear + 1

The second case happens because we 're using circular increment so we could have rear loop back around the array and be just right behind (1 index behind) front, which means the array is full. 

Finding the number of elements in a circular queue 

Time Complexity 

The enqueue and dequeue operations of a circular queue is O(1) (for array implementations). 

###### Applications of a Circular Queue 
CPU scheduling 
Memory management 
Traffic management 

ArrayDeque provides a resizable array that's an implementation of the dequeue interface. It's also known as a double ended queue or array deck. It grows and allows for insertion and removal from both size. 

It has no capacity restrictions
It's not thread-safe 
Null elements aren't allowed
It's likely faster than a stack when used as a stack 
It's likely faster than linked list when used as a queue 

The LinkedList class also supports Dequeue and supports null values but takes up way more memory. 

About ArrayDequeue vs vs Dequeue (Linked List): 
About ArrayDequeue vs vs Queue (Linked List): https://stackoverflow.com/questions/56767560/arraydeque-vs-linkedlist-as-queue-for-level-order-traversal

Use ArrayDequeue instead of Stack and also Queue. It's faster than both and has many other advantages. 

### Trees
A tree is a nonlinear hierarchical data structure that consists of nodes connected by edges. 

Why a tree data structure? 

Other data structures such as arrays, linked lists, stacks and queues are linear data structures that store data sequentially. In order to perform any operation in a linear data structure, the time complexity increases with the increase in data size. 

Different data structures allow quicker and easier access to data as there're non-linear data structures. 
Tree Terminology
Source to image above: https://www.tutorialspoint.com/data_structures_algorithms/tree_data_structure.htm

node - an entity that contains a key or value and pointers to its child nodes 
leaf node (external nodes) - nodes with no children (the last nodes of each path)
internal node - the node having at least one child node 
edge - the link between any two nodes 


root - the topmost node a tree
height of a node - the number of edges from the node to the deepest leaf node (the longest path from the node to a leaf node)
depth of a node - the number of edges from the root node to the node 
height of a tree - the height of the root node or the depth of the deepest leaf node 

degree of a node - the number of subtrees of a node 
degree of a tree - the maximum degree of all nodes in the tree 
forest - a collection of disjoint trees is called a forest 


You can create a forest by cutting the root of a tree. 

#### Types of Tree: 
Binary Tree
Binary Search Tree
AVL Tree 
B-Tree

#### Applications of Trees
Binary Search Trees are used to quickly determine whether an element is present in a set or not
heap is a kind of tree that's used in heap sort 
a modified version of a tree called tries (pronounced "try") is used in modern routers to store routing information 
most popular databases use B-Trees and T-Trees, which are variants of the tree structure to store data 
compilers use a syntax tree to validate the syntax of every program you write 

### Tree Traversal 

Traversing a tree means visiting every node in the tree. You might for example want to add all the values in the tree or find the largest one. For all of these operations, you will need to visit each node in the tree. 

Unlike linear data structures, trees can be traversed in different ways. 

Trees are filled with nodes which are made up of data and pointers to the left or right node (in the case of a binary tree). 

struct node {
    int data;
    struct node* left;
    struct node* right;
}

Since the node pointed to by the left and right might have other left and right children, we should think of them as sub trees instead of sub nodes. 

So every tree is a combination of a node carrying data and two subtrees. 

#### Inorder traversal 

Visit all nodes in the left subtree
Visit the node 
Visit all the nodes in the right subtree 

inorder(node.left)
visit(node)
inorder(node.right)

#### Preorder traversal 

Visit the node 
Visit all nodes in the left subtree
Visit all the nodes in the right subtree 

visit(node)
preorder(node.left)
preorder(node.right)

#### Postorder traversal 

Visit all nodes in the left subtree
Visit all the nodes in the right subtree 
Visit the node 

postorder(node.left)
postorder(node.right)
visit(node)

#### Example
In Order: A B C D E F G H I
Pre Order: F B A D C E G I H  
Post Order: A C E D B H I G F

We could use a stack to keep track of nodes to traverse but recursion keeps track of this for us (it has a call stack). 

Resources: 

Tree Height vs Depth (the image on tree height and depth of Programiz is wrong): https://www.baeldung.com/cs/tree-depth-height-difference

About Trees: https://www.programiz.com/dsa/trees

Post-order Tree Traversal: https://www.youtube.com/watch?v=4zVdfkpcT6U
Types of Binary Tree: 

### Binary Tree

#### Full Binary Tree (Proper Binary Tree) 
A binary tree where every node has 0 or 2 children 

#### Perfect Binary Tree
A binary tree where every internal node has two child nodes and all leaf nodes are at the same level

#### Complete Binary Tree
A binary tree in which every level, except possibly the last is completely filled and all nodes are as far left as possible


#### Degenerate or Pathological Tree 
A binary tree where every internal node has one child node (either left or right). These trees are performance-wise the same as linked list. 

#### Skewed Binary Tree 
A type of degenerate tree. There are two types. 

#### Left Skewed Binary Tree 
All nodes have a left child or no child at all (all the right nodes remain null) 

#### Right Skewed Binary Tree 
All nodes have a right child or no child at all (all the left nodes remain null) 

#### Balanced Binary Tree (height balance binary tree) 
A binary tree where the height of the left and right subtree of any node doesn't differ by more than 1. 

### Binary Search Tree (BST) 

Binary Search Tree is a node-based binary tree data structure which has the following properties:

The left subtree of a node contains only nodes with keys lesser than the node’s key
The right subtree of a node contains only nodes with keys greater than the node’s key
The left and right subtree each must also be a binary search tree


The worst case is Binary Search Trees comes when you're dealing with a degenerate tree (which is also a tree that's unbalanced). So you'll need to traverse through more nodes to find the value/node you're looking for. 

So the height of the binary search tree becomes n so its time complexity is O(n). 

The best case is when the binary search tree is balanced. So the height of the binary search tree and its time complexity becomes log(n). 

#### Duplicates in Binary Search Trees
Whether or not duplicates are allowed depends on the implementation of the binary search tree.  Although by most definitions, binary search trees don't allow duplicates. The implementation of the insert operation of the binary search tree on Programiz doesn't allow duplicates. 

Binary Search Tree Time Complexity

Source: https://en.wikipedia.org/wiki/Binary_search_tree


#### Self Balanced & Height Balanced Binary Search Tree
In computer science, a self-balancing binary search tree (BST) is any node-based binary search tree that automatically keeps its height (maximal number of levels below the root) small in the face of arbitrary item insertions and deletions.[1] These operations when designed for a self-balancing binary search tree, contain precautionary measures against boundlessly increasing tree height, so that these abstract data structures receive the attribute "self-balancing".
For height-balanced binary trees, the height is defined to be logarithmic O(log n) in the number n of items. This is the case for many binary search trees, such as AVL trees and red–black trees. Splay trees and treaps are self-balancing but not height-balanced, as their height is not guaranteed to be logarithmic in the number of items.
Self-balancing binary search trees provide efficient implementations for mutable ordered lists, and can be used for other abstract data structures such as associative arrays, priority queues and sets.

About: https://en.wikipedia.org/wiki/Self-balancing_binary_search_tree

#### Red-Black Tree
In computer science, a red–black tree is a kind of self-balancing binary search tree. Each node stores an extra bit representing "color" ("red" or "black"), used to ensure that the tree remains balanced during insertions and deletions.[3]
When the tree is modified, the new tree is rearranged and "repainted" to restore the coloring properties that constrain how unbalanced the tree can become in the worst case. The properties are designed such that this rearranging and recoloring can be performed efficiently.
The re-balancing is not perfect, but guarantees searching in O (log ⁡ n) time, where n is the number of entries. The insert and delete operations, along with the tree rearrangement and recoloring, are also performed in O (log ⁡ n) time.[4]
Tracking the color of each node requires only one bit of information per node because there are only two colors. The tree does not contain any other data specific to it being a red–black tree, so its memory footprint is almost identical to that of a classic (uncolored) binary search tree. In many cases, the additional bit of information can be stored at no additional memory cost.
About: https://en.wikipedia.org/wiki/Red–black_tree (Wikipedia Time Complexity is wrong)

#### Applications of Red Black Trees
As of Java 8, the HashMap has been modified such that instead of using a LinkedList to store different elements with colliding hashcodes, a red–black tree is used. This results in the improvement of time complexity of searching such an element from O (m) to O (log ⁡ m) where m is the number of elements with colliding hashcodes.

### TreeMap
TreeMap data structure. TreeMap is implemented as a red black tree, which is a self-balancing binary search tree.
Tries
In computer science, a trie, also called digital tree or prefix tree,[1] is a type of k-ary search tree, a tree data structure used for locating specific keys from within a set. These keys are most often strings, with links between nodes defined not by the entire key, but by individual characters. In order to access a key (to recover its value, change it, or remove it), the trie is traversed depth-first, following the links between nodes, which represent each character in the key.
Unlike a binary search tree, nodes in the trie do not store their associated key. Instead, a node's position in the trie defines the key with which it is associated. This distributes the value of each key across the data structure, and means that not every node necessarily has an associated value.
All the children of a node have a common prefix of the string associated with that parent node, and the root is associated with the empty string. This task of storing data accessible by its prefix can be accomplished in a memory-optimized way by employing a radix tree.
Though tries can be keyed by character strings, they need not be. The same algorithms can be adapted for ordered lists of any underlying type, e.g. permutations of digits or shapes. In particular, a bitwise trie is keyed on the individual bits making up a piece of fixed-length binary data, such as an integer or memory address. The key lookup complexity of a trie remains proportional to the key size. Specialized trie implementations such as compressed tries are used to deal with the enormous space requirement of a trie in naive implementations.

The reason isEndOfWord is used in search operation (at the end when verifying if a key exists within a trie) for a trie and is a general attribute for a node, is because it’s possible that a particular string (key) exists in a trie that wasn’t added explicitly. For example if you added the string “too”, the string “to” would also be in the trie. That isEndOfWord thus is needed to keep track of what has been explicitly added into the trie and thus is an actual key. 


About: https://en.wikipedia.org/wiki/Trie
Explains the concept of a trie better than the first link: https://www.hackerearth.com/practice/data-structures/advanced-data-structures/trie-keyword-tree/tutorial/ Has the best code for the implementation of a trie in Java: https://www.geeksforgeeks.org/trie-delete/

#### Uses of Traversals
In-Order: In the case of a binary search tree, it gets the elements in non-decreasing order. To get the nodes in non-increasing order you can do a variation of in-order traversal where it's reversed. 

Increasing vs Non Decreasing 
Increasing means that every element is greater than the one before it. Non-decreasing means that no element is less than the element before it, or in other words: that every element is greater than or equal to the one before it.

Increasing - 1 2 3 4
Nondecreasing - 1 1 2 3

Pre-order: Is used to create a copy of a tree. 

Post-order: Is used to delete the tree. 

There's no standard binary tree data structure in Java due to its ambiguity.


### Graphs
A graph is a collection of nodes that have data and are connected to other nodes. 

On facebook, everything is a node. This includes user, photo, album, event, group, comment, video...anything that has data is a node. 

Every relationship is an edge from one node to another. When you post a photo, join a group, etc. a new edge is created for that relationship. 

A graph is a data structure that consists of 
A collection of vertices V 
A collection of edges E, represented as a pair of ordered vertices (u, v)

Graphs are represented in two ways: 
#### Adjacency Matrix

An adjacency matrix is a 2D array of V x V vertices. Each row and column represents a vertex. It's faster for edge lookup (finding if an edge exists between vertex A and vertex B) but it takes up more space because we have to reserve space for every possible link (edge) between all vertices (V x V). 

#### Adjacency List

An adjacency list represents a graph as an array (actually a resizable array, which is a list) of lists. It's more space efficient since we only need to reserve space for links (edges) that exist. 



#### Dense and Sparse Graph 
In mathematics, a dense graph is a graph in which the number of edges is close to the maximum number of edges. The opposite, a graph with only a few edges (much less than the maximum), is a sparse graph. The distinction between sparse and dense graphs is rather vague, and depends on the context. 

In practice an adjacency list tends to be better for most tasks since adjacency matrices are more suited to dense graphs. Most graphs out in the wild don't have that many connections and thus aren't dense. 

#### Applications of DFS: 
Finding the path between two vertices u and v
Test if a graph is bipartite
For finding the strongly connected components of a graph
For detecting cycles in a graph
For an unweighted graph, the DFS traversal of the graph produces the minimum spanning tree 
We can perform topological sorting, which is used to schedule jobs from given dependencies among jobs. Topological sorting can be done using the DFS algorithm

To do DFS on a disconnected graph we can call the DFS algorithm on every node that hasn't been visited. The time complexity will remain the same. 

If two vertices in a graph are connected by an edge, we say that the vertices are adjacent. 

A vertex v is incident to an edge e if it's one of the two vertices the edge connects.
Breath First Search is used in peer to peer networks like BitTorrent to find all neighbor nodes
BFS can also be used to find the shortest path and the minimum spanning tree in an unweighted graph. In an unweighted graph, the shortest path is the path with the least number of edges. Also in the case of unweighted graphs, any spanning tree is a minimum spanning tree and we can use BFS or DFS for finding a spanning tree. 
Crawlers in Search Engines 

connected graph - a graph is connected if any two vertices in the graph are connected by a path
disconnected graph - a graph is disconnected if at least two vertices of the graph aren't connected by a path.  If a graph is disconnected then every maximal connected subgraph of G is called a connected component of the graph G. 

subgraph - a graph whose vertices and edge sets are subsets of another graph. The other graph (that's has a subgraph of a graph) is said to be a supergraph. 

cycle - a path that starts from a given vertex and ends at the same vertex is called a cycle 

Below the nodes 3 - 4 - 5- 6 - 3 form a cycle:

tree - an undirected graph in which any two vertices are connected by exactly one path or equivalently a connected acyclic undirected graph

directed graph (digraph) - is a graph where edges are directed from one vertex to another. This is in contrast to an undirected graph where edges are bidirectional. 

directed acyclic graph (DAG) - is a digraph with no cycle. Note that DAGs can have disconnected parts since the only requirement are that they're directed and acyclic. If you want to say that a DAG is connected, you could say "connected DAG". 

Relationships between Graphs and Trees 
Standard definition of a graph
Recall that a graph, G, is a tree iff the following two conditions are met:
G is fully connected. In other words, for every pair of nodes in G, there is a path between them.
G contains no cycles. In other words, there is exactly one path between each pair of nodes in G.

#### Better definition of a graph 
Depending on how much graph theory you know, there's a better definition for determining whether or not a given graph is a tree.
For the graph to be a valid tree, it must have exactly n - 1 edges. Any less, and it can't possibly be fully connected. Any more, and it has to contain cycles. Additionally, if the graph is fully connected and contains exactly n - 1 edges, it can't possibly contain a cycle, and therefore must be a tree!
These facts are fairly straightforward to prove. We won't go into why they are true here, but if you're not familiar with these facts, then we recommend reading up on graph theory. It is very important to be confident with graph theory in-order to pass the interviews at a top tech company.

Good leetcode problem that highlights this: https://leetcode.com/problems/graph-valid-tree/solution/

### Heap
A heap is a complete binary tree that satisfies the heap property. 
Heap Operations 
Heapify - a process to rearrange the heap in order to maintain the heap-property. It is done when a certain node causes an imbalance in the heap due to some operation on that node. 
Delete Element from Heap
Peek (Find max/min) 

Peek operation returns the maximum element from max heap or minimum element from min heap without deleting the node. 

Extract max/min 

Remove the max or min value and return it from a max/min heap. 

Time Complexity: 

Finding the min and max element of a heap is O(1). 

Source: https://iq.opengenus.org/time-and-space-complexity-of-heap/#gettingmaxvalueminvalue

#### Heap Applications
Heap is used while implementing a priority queue

### Dijkstra's Algorithm

### Heap Sort 

#### When to use a heap: 
When you need quick access to the largest or smallest item because that item will always be the first element or at the root of the tree. 

Resources: 

Introduction to heaps: https://www.programiz.com/dsa/heap-data-structure

More about heaps (up heapify down heapify):  
https://afteracademy.com/blog/operations-on-heapshttps://afteracademy.com/blog/operations-on-heaps

### Priority Queue (Heap in Java)
A priority queue is a data structure in which each element is associated with a priority and is served according to its priority. If elements with the same priority occur, they are served according to their order in the queue. 

PriorityQueue<E> class in Java: 
Union Find
Union find is a very useful algorithm that can be used to solve many graph problems. In computer science, a disjoint-set data structure, also called a union–find data structure or merge–find set, is a data structure that stores a collection of disjoint (non-overlapping) sets. Equivalently, it stores a partition of a set into disjoint subsets. It provides operations for adding new sets, merging sets (replacing them by their union), and finding a representative member of a set. The last operation makes it possible to find out efficiently if any two elements are in the same or different sets.

#### Java Implementation 
Firstly, here's the code without the optimizations. Below, I've also included the code with the optimizations. If you're new to union find, then I recommend reading the code without optimizations first, as it's a lot easier to understand! Source: https://leetcode.com/problems/graph-valid-tree/solution/

class UnionFind {
private int[] parent;

// For efficiency, we aren't using makeset, but instead initialising
// all the sets at the same time in the constructor.
public UnionFind(int n) {
    parent = new int[n];
    for (int node = 0; node < n; node++) {
        parent[node] = node;
    }
}

// The find method, without any optimizations. It traces up the parent
// links until it finds the root node for A, and returns that root.
public int find(int A) {
    while (parent[A] != A) {
        A = parent[A];
    }
    return A;
}

// The union method, without any optimizations. It returns True if a
// merge happened, False if otherwise.
public boolean union(int A, int B) {
    // Find the roots for A and B.
    int rootA = find(A);
    int rootB = find(B);
    // Check if A and B are already in the same set.
    if (rootA == rootB) {
        return false;
    }
    // Merge the sets containing A and B.
    parent[rootA] = rootB;
    return true;
}
These are the solutions using the optimizations path compression and union by size.
class UnionFind {
private int[] parent;
private int[] size; // We use this to keep track of the size of each set.

// For efficiency, we aren't using makeset, but instead initialising
// all the sets at the same time in the constructor.
public UnionFind(int n) {
    parent = new int[n];
    size = new int[n];
    for (int node = 0; node < n; node++) {
        parent[node] = node;
        size[node] = 1;
    }
}

// The find method, with path compression. There are ways of implementing
// this elegantly with recursion, but the iterative version is easier for
// most people to understand!
public int find(int A) {
    // Step 1: Find the root.
    int root = A;
    while (parent[root] != root) {
        root = parent[root];
    }
    // Step 2: Do a second traversal, this time setting each node to point
    // directly at A as we go.
    while (A != root) {
        int oldRoot = parent[A];
        parent[A] = root;
        A = oldRoot;
    }
    return root;
}

// The union method, with optimization union by size. It returns True if a
// merge happened, False if otherwise.
public boolean union(int A, int B) {
    // Find the roots for A and B.
    int rootA = find(A);
    int rootB = find(B);
    // Check if A and B are already in the same set.
    if (rootA == rootB) {
        return false;
    }
    // We want to ensure the larger set remains the root.
    if (size[rootA] < size[rootB]) {
        // Make rootB the overall root.
        parent[rootA] = rootB;
        // The size of the set rooted at B is the sum of the 2.
        size[rootB] += size[rootA];
    }
    else {
        // Make rootA the overall root.
        parent[rootB] = rootA;
        // The size of the set rooted at A is the sum of the 2.
        size[rootA] += size[rootB];
    }
    return true;
}
Primitive Recursive Function 
https://en.wikipedia.org/wiki/Primitive_recursive_function

Time Complexity
The time complexity for all operations near constant amortized time. So we can consider them to just be O(1) for simplicity. 

#### Signed vs Unsigned 
The term "unsigned" in computer programming indicates a variable that can hold only positive numbers (and 0). The term "signed" in computer code indicates that a variable can hold negative and positive values (and 0).


In Java by default, the int data type is a 32-bit signed two’s complement integer, which has a minimum value of -2^31 and a maximum value of 2^31-1.  Java only supports signed types (except for char). Although Java 8 has operations that support unsigned types (working with unsigned types often causes confusion). These are added to the wrapper classes like Integer and Long. 

---
## Algorithms Deep Dive
Breath First Search (BFS) and Depth First Search (DFS)

DFS depth first search and BFS breadth first search are used to traverse a tree/graph. 

Breadth First Search is an algorithm that starts at the root of the tree (or some arbitrary node of a graph) but unlike DFS it visits the neighbor nodes first before moving to the next level neighbors. In other words, BFS explores vertices in the order of their distance from the source vertex, where distance is the minimum length of a path from the source vertex to the node. 

Depth First Search - starts at the root of the tree (or some arbitrary node in a graph) and explores as far as possible along each branch before backtracking. It uses a stack to remember to get the subsequent vertex and to start a search, whenever a dead-end appears in any iteration. 
BFS traverses according to tree level while DFS traverses according to tree depth. 

The time complexity of BFS if the entire tree is traversed is O(V), where V is the number of nodes. In the case of a graph, the time complexity is O(V+E), where V is the number of vertices and E is the number of edges.



Time Complexity of BFS and DFS: 

About BFS (Shows the algorithm in steps): https://www.educative.io/edpresso/what-is-breadth-first-search

About DFS (Shows the algorithm in steps):
https://www.educative.io/edpresso/what-is-depth-first-search

Level Order Traversal and Breath First Search are the same thing and can be used interchangeably. The term is often used to compare to in-order, pre-order and post-order traversal of DFS. 
Linear Search 
In a linear search given an array of n elements and where we want to search a given element x in the array, we go one by one (and iterate through the array) and compare each element in the array by x. 

Start from the leftmost element of arr[] and one by one compare x with each element of arr[]
If x matches with an element, return the index.
If x doesn’t match with any of elements, return -1.

The time complexity is simply O(n). 
Binary Search 
Given a sorted array of n elements, we want a function to search a given element x in the array. A simple approach would to do a linear search.

Only works on something that’s sorted. Although binary search can be applied to other things besides arrays like strings.  

The reason we do m = l + (r - l) / 2 to get the mid point is because we want to avoid the possible integer overflow from l + r. So we do this by adding the difference of r and l over 2. 

The time complexity of binary search is O(log2(n)) or just O(log(n)) 

About binary search: https://www.youtube.com/watch?v=T2sFYY-fT5o
Sorting
Time Sort
Timesort - a hybrid stable sorting algorithm, derived from merge sort and insertion sort, designed to perform well on many kinds of real-world data. It was implemented by Tim Peters in 2002 for use in Python. The algorithm finds subsequences of the data that are already ordered (runs) and uses them to sort the remainder more efficiently. This is done by merging runs until certain criteria are fulfilled.  Timsort has been Python's standard sorting algorithm since version 2.3. It is also used to sort arrays of non-primitive type in Java SE 7,[4] on the Android platform,[5] in GNU Octave,[6] on V8,[7] and Swift.[8]

More about Timsort: https://en.wikipedia.org/wiki/Timsort
Sliding Window

About: https://www.baeldung.com/cs/sliding-window-algorithm
Topological Sort
The canonical application of topological sorting is in scheduling a sequence of jobs or tasks based on their dependencies. 

Topological sorting for Directed Acyclic Graph (DAG) is a linear ordering of vertices such that for every directed edge u v, vertex u comes before v in the ordering. Topological Sorting for a graph is not possible if the graph is not a DAG.
For example, a topological sorting of the following graph is “5 4 2 3 1 0”. There can be more than one topological sorting for a graph. For example, another topological sorting of the following graph is “4 5 2 3 1 0”. The first vertex in topological sorting is always a vertex with in-degree as 0 (a vertex with no incoming edges).


About: https://www.geeksforgeeks.org/topological-sorting/
https://en.wikipedia.org/wiki/Topological_sorting
Backtracking
Backtracking is an algorithmic technique that considers searching in every possible combination for solving a computational problem.
It is known for solving problems recursively one step at a time and removing those solutions that that do not satisfy the problem constraints at any point of time.
It is a refined brute force approach that tries out all the possible solutions and chooses the best possible ones out of them.
The backtracking approach is generally used in the cases where there are possibilities of multiple solutions.

About: https://www.interviewbit.com/courses/programming/backtracking/

Good overview of many backtracking problems in Java: https://leetcode.com/problems/permutations/discuss/18239/A-general-approach-to-backtracking-questions-in-Java-(Subsets-Permutations-Combination-Sum-Palindrome-Partioning)

Time Complexity
The time complexity of backtracking algorithms goes as follows: Total time = Time Cost of One Path * Number of Paths

i.e. The leetcode problem: https://leetcode.com/problems/letter-combinations-of-a-phone-number/solution/ has the following time complexity below.
For each combination, we need O(N) time.
There are total O(4^N) combinations.
Useful Java Methods
String.valueOf() - convert an int, long, double, float, character to a string 
WrapperClass.toString() - if you have a wrapper class like Integer just invoke the .toString() method. (It’s better to do this for wrappers but doing String.valueOf() is recommended for primitives) 
stringName.substring(beginIndex) - goes from the beginning index (inclusive) till the end of the string 
stringName.substring(beginIndex, endIndex) - the begin index is inclusive while the endIndex is exclusive (O(n), where n is the number of characters in a string )
stringName.length() - returns the length of a string (counts whitespaces)
stringName.indexOf(String str) - returns the index within this string of the first occurrence of the specified substring. If it does not occur as a substring, -1 is returned (O(m * n), where n and m are the length of the search string and search pattern respectively). O(m*n)  is worst case, not typical. Typical is O(n) . When you say O(m*n)  you're totally ignoring the short-circuiting of matching pattern to current position, which will stop as soon a pattern doesn't match. That would rarely progress past the 3rd character of the pattern. indexOf()  even has specific optimization to look for first character before even entering the pattern matching logic. Amortized, it's probably something like O(1.1 * n) , so O(n).https://stackoverflow.com/questions/12752274/java-indexofstring-str-method-complexity
stringName.indexOf(String str, int strt) - strt - is an integer, which represents the starting index
stringName.indexOf(int char) - an int value, representing a single character, e.g “A” or a unicode value
stringName.indexOf(int char, int str) 
stringName.charAt() - gets the character of a string at a specific index (this is constant time for String, StringBuilder and StringBuffer)
StringBuilder builder = new StringBuilder(inputString); - creates a new StringBuilder with the specified string
StringBuilder.deleteChartAt() - deletes a char at a specific index (this is O(n) for StringBuffer and StringBuilder). To delete a single character from a string, convert the string to a string builder, then call this method and change it back to a string. 
stringBuilderName.append(X x) - method appends the string representation of the X type argument to the sequence (It’s O(1) for single characters and the cost is proportional to the number of characters in the string. However a StringBuilder is implemented under the hood as a dynamic array. So allocating any number of characters will still take a constant amount of time although it will take longer depending on the number of characters. Still we can consider this O(1) because allocating characters to an array will take constant time (constant time by a number is still constant time, so it really depends on how you look at it). If there isn’t enough space in a string builder/buffer, new space needs to be made (which will involve copying everything to a new buffer), which causes O(n). This takes time proportional to the current size of String Builder or String Buffer. If this happens the size of String Builder or String Buffer will be doubled. In summary we can say StringBuilder has an amortized time of O(1) because the worst case is overly pessimistic. Time complexity of append: https://www.quora.com/What-is-the-complexity-of-Java-StringBuffer-append 
stringBuilderName.capacity() - returns the current capacity (as an int, note this isn’t necessarily the length of the string) 
stringBuilderName.length() - returns the length (character counter) (as an int)
stringBuilderName.reverse() - reversed the character sequence (O(n))
stringBuilderName.delete(int start, int end) - this method removes the characters in a substring of this sequence (O(n)) (the start is inclusive while the end is exclusive just like String.delete(int start, int end))
stringBuilderName.deleteCharAt() - takes in an integer and deletes a char at the specified index (O(n))
stringBuilderName.indexOf() - returns the index within this string of the first occurrence of the specified substring (returns as an int and has O(n * m) time complexity)
StringBuilder.setLength(0) - this is the best way to clear a string builder. This doesn’t involve any garbage collection or new allocation. This resets the internal buffer length to 0. The original buffer length stays in memory so new memory allocation is not needed. 
stringName.split() VV

Splitting an IP address: 
Source: https://stackoverflow.com/questions/15310505/manipulating-ip-addresses-split-string-on-character

Regular expression - used for defining String patterns that can be used for searching, manipulating and editing a text. These expressions are also known as Regex (short form of regular expressions). 


About regular expressions: https://beginnersbook.com/2014/08/java-regex-tutorial/

stringName.compareTo() - is used for comparing two strings lexicographically. Each character of both strings is converted to a Unicode value for comparison. If both strings are equal the method returns 0, else it returns a positive value (if the first string is lexicographically stronger than the second (comes after) or negative value (if the first string is lexicographically weaker than the second string) Any character is lexicographically stronger (comes after so compareTo would be positive) than the empty string

Example: 
The method is case sensitive with lowercase being lexicographically stronger than upper case characters. If you want to ignore case when comparing use compareToIgnoreCase() which does the exact same thing except ignores case. You can find the length of a string using stringName.compareTo(“"). If we compare a string with an empty string using the compareTo() method then the method would return the length of the non-empty string.

The actual result always returns the length of the lexicographically stronger string (either positive or negative). 

0 in ASCII code is null. So you can assign 0 to a character to make it an empty string or use the string ‘\u0000’ or '\0’, which is the same as 0. We can do that by also using Character.MIN_VALUE, which assigns the smallest value of type char, ‘\u0000’.

So we can do: 

char x = 0;
char x = ‘\0’;
char x = ‘\u0000’;
char x = Character.MIN_VALUE; 

Char means exactly one character. You can’t assign zero characters to this type (this is because it’s a primitive, which all must have some value and can’t be null like objects). 

Fun fact: A space character has an ASCII value of 32.
objectName.toString() - used to get a string representation of an object 
Character.getNumericValue(char c) - takes a character as an argument and converts it into an integer (ASCII). Note you can do this implicitly by doing something like int x = ‘h’. Use Integer.parseInt() if you want to convert from an int represented as a string and if you’re allowed to. 
Character.isDigit(char c) - determines if the specified char value is a digit (returns a boolean) 
Character.valueOf(char c) - Returns the instance of a Character which represents the specified character value. (Don’t use Character c = new Character(char) as it’s depricated)
Array.length - gets the length of an array (don’t confuse this length method with the one from string which requires a parenthesis) 
Integer.parseInt(String s) - converts a string to an integer
Integer.parseInt(String s, int redix) - when you use this method and input the integer “2" for the redix, it will convert a binary number given as a string to a decimal. Look at the example below. 

String binaryString="1010";  
int decimal=Integer.parseInt(binaryString,2);  

More info about redix: This returns an integer, given a string representation of decimal, binary, octal, or hexadecimal (radix equals 10, 2, 8, or 16 respectively) numbers as input.

If we wanted to convert to decimal we’d just use 16. 

int b = Integer.parseInt("444",16);  // b is now 1092 (decimal) 

About Integer.parseInt(): This method is used to get the primitive data type of a certain String.parseXxx() is a static method and can have one argument or two.

This can be used with double as well. 

Double.parseDouble(String s) 
Double.parseDouble(String s, int radix)
Integer.toHexString(int num) - converts a decimal integer to a hex string so this method returns a string. 
Math.pow(num, amount to square) - squares a number (note this returns a double so if you want an int, make sure to cast 
Collections.max(map) - gets the maximum value from a map (hashmap)
Collections.min(map) - gets the minimum value from a map (hash map)
Arrays.toString(Object[] array) - returns an array as a string  (for single dimension arrays). Don't use array.toString(). Java's toString() for an array is to print [, followed by a character representing the type of the array's elements (in your case C for char), followed by @ then the "identity hash code" of the array (think of it like you would a "memory address").
Arrays.deepToString(Object[] array) - returns an array as a string (for multi dimensional arrays, will work with 3d arrays) https://www.programiz.com/java-programming/examples/print-array
string.toCharArray() - converts a string into an array of characters
Arrays.sort() - use that to sort an array according to it’s natural order (for an int array it’s smallest to largest) (O(nlog(N) is if input is Object[] or O(n^2) (but O(nlogn in best and average case) if input is an int[]. To understand why go to the “Sorting” section)
HashMap<String, Integer> map = new HashMap<String, Integer>() (an example of a hash map declaration, where String is the type of the key and Integer is the type of the value

If you want to convert a hash map to a 2D array, you can do the following: 

String[][] array = new String[map.size()][2];
int count = 0;
for(Map.Entry<String,String> entry : map.entrySet()){
    array[count][0] = entry.getKey();
    array[count][1] = entry.getValue();
    count++;
}

map.put(Object key, Object value) - used to insert a key-value pair into the map. This will replace any existing values if a key doesn’t exist
map.get(someKeyName) - takes in a key to get the value associated with that key 
map.getOrDefault(someKeyName, defaultValue) - used to get the value mapped with the specified key. If no value is mapped with the provided specified key, the default value is returned.
map.remove(someKeyName) - takes in a key to remove the item (key and it’s associated value from the hash map but it will also return the value. This method can be called is such a way (normally (map.remove(“key1”)) that the returned value is ignored.) 
map.clear() - remove all items in a hash map O(n). This keeps the array the same size but just remove all the elements.
map.size() - returns the size of the hash map as an int
map.isEmpty() - used to check whether the map is empty or not. Returns true if the map is empty. 
map.containsKey(Object key) - returns true if for a specifying key the mapping is present in the hash map (time complexity is O(1)) 
map.containsValue(Object value) - returns true if one or more keys is mapped to a specified value (time complexity is O(n) because without the key the hash map doesn’t know where it is and the algorithm has to go all over the values stored in the map)
map.putAll(Map M) - used to copy all of the elements from one map into another
Map<Character, String> letters = Map.of( '2', "abc", '3', "def", '4', "ghi", '5', "jkl", '6', "mno", '7', "pqrs", '8', "tuv", '9', "wxyz"); (example usage of Map.of())
for (String i : map.keySet()) {  
	    		System.out.println(i);
		}  (looping through a hash map. This will get each key in the hash map. map.keySet() is used to return a set view of the keys. So it returns a Set<Datatype> reference variable. 
for (String i : map.values()) {
    			System.out.println(i);
		} (looping through a hash map. This will get each value in the hash map). map.values() is used to return a Collection view of the values in the hash map. So it returns a (Collection<DataType>)  (interface) reference variable. 
We can also iterate over a hash map using Map.entrySet() in a for loop with the help of the Map.Entry<K, V> interface. This returns a collection view (Set<Map.Entry<K, V>>) of the mappings contained in this map. So we can iterate over key-value pairs using getKey() and getValue() methods of Map.Entry<K, V>. This is the most common method if you need both keys and values in the loop. 

  for (Map.Entry<String, String> entry : hashMapName.entrySet()) {
      System.out.println("Key = " + entry.getKey());
      System.out.println("Value = " + entry.getValue());
  }
map.entrySet().iterator().next().getValue() - gets the first value in a hash map (should really only be used for a linked hash map since hash maps don’t guarantee that insertion order will be maintained
map.entrySet().iterator().next().getKey() - gets the first key in a hash map (only makes sense to do this for linked hash map or tree map since they maintain some kind of key order)
Explanation: Let’s say after the for loop, map = {e:1 ,d:5, f:8} for example. Here map.size() > 0, so map.entrySet().iterator().next().getValue() will be executed.
map.entrySet() will return a Set of Map.Entry<K, V> objects ( Set<Map.Entry<K, V>>), like this {<e,1>, <d,5>, <f,8>} where each element is a Map.Entry object. If you want to loop a set, you use an iterator, that is why the map.entrySet().iterator() is used. Then the map.entrySet().iterator().next()
will return the next Map.Entry object added to the map by starting at the first one (LinkedHashMap guarantee that). In the above example, <e,1> entry will be return (he only need the first unique). When you have a Map.Entry<K, V> object, you can call getKey() to return the key or getValue() to return the value of that entry. Here, he wanted the position, so he called getValue() and that lead to:
map.entrySet().iterator().next().getValue(). In the example, 1 will be returned.

If you want to think about it another way look at the code below. It will show you how to use iterator with Map.Entry<> to get the next elements more manually with an iterator instead of using the traditional for each loop method. 

long i = 0;
Iterator<Map.Entry<Integer, Integer>> it = map.entrySet().iterator();
while (it.hasNext()) {
    Map.Entry<Integer, Integer> pair = it.next();
    i += pair.getKey() + pair.getValue();
}
Collections.reverseOrder() - reverse the natural ordering on a collection of objects (that implement the comparable interface)
Comparator<Datatype> compName = new Comparator<Datatype>() { 
	    public int compare(Object obj1, Object obj2) {
	    // comparison logic 
		}
		};   // remember the semi colon. Also to use it do
// Arrays.sort(arrayName, compName); 
// ^^ Remember that this mutates the original array (it’s return type is void). 
Arrays.sort(arr, comparator) - takes in a comparator to define a custom sort order
Iterator<Datatype> iterator = new Iterator<>(); 
iterator.hasNext() - It returns true if Iterator has more element to iterate.
iterator.next() - It returns the next element in the collection until the hasNext()method return true. This method throws ‘NoSuchElementException’ if there is no next element.
iterator.remove() - It removes the current element in the collection. This method throws ‘IllegalStateException’ if this function is called before next( ) is invoked.
TreeMap methods: https://docs.oracle.com/javase/7/docs/api/java/util/TreeMap.html (floor and ceiling methods = are inclusive to lower and upper bounds respectively while lower and upper key methods are exclusive to the lower and upper bounds respectively) 
TreeSet methods: https://docs.oracle.com/javase/7/docs/api/java/util/TreeSet.html
hashSet.add(E e) 
hashSet.remove(Object o)
hashSet.contains(Object o)
hashSet.clear() (Time complexity is O(n) just like with a hash map)
hashSet.iterator() (i.e. HashSet<String> set = new HashSet<String>(); Iterator<String> value = set.iterator();)
hashSet.isEmpty()
hashSet.size() 
hashSet.clone() - makes a shallow copy of the set 
hashSet.equals() - used to compare if two hash sets are equal 
hashSet.removeAll(Collection c) - used to remove all elements from the collection which are present in the set. The method returns true if this set changed as a result of the call
hashSet.addAll(Collection c) - used to append all of the elements from the mentioned collection to thee existing set. The elements are added randomly without following any specific order. 
hashSet.containsAll(Collection c) - used to check whether the set contains all the elements present in the given collection or not. This method return true if the set contains all the elements and returns false if any of the elements are missing.
hashSet.retainAll(Collection c) - used to retain all the elements from the set which are mention in the given collection (think of this as the intersection between two collections). This method returns true if this set changed as a result of the call). https://www.geeksforgeeks.org/abstractcollection-retainall-method-in-java-with-examples/
hashSet.toArray() - used to form an array of the same elements as that of the set
hashSet.toString() - used to return a string representation of the elements of the HashSet Collection
Integer.MAX_VALUE - gets the max value of an integer, which is 2^31 - 1. Can be used like so:
int x = Integer.MAX_VALUE;
Integer.MIN_VALUE - gets the min value of an integer, which is -2^31
Math.max(int num1, int num2) - gets the maximum value of two integers 
Math.min(int num2, int num2) - gets the minimum value of two integers 
Math.abs(int num) - gets the absolute value of a number. If the argument is not negative, the argument is returned. If the argument is negative, the negation of the argument is returned. Note that if the argument is equal to the value of Integer.MIN_VALUE, the most negative representable int value, the result is that same value, which is negative.
List<Datatype> newList = new ArrayList<Datatype>(otherList) - creates a copy of a list. This also makes it so that the two lists refer to different objects (have different references). 
arrayList.add(E e) - adds an element to the array list
arrayList.add(int index, E element) - adds an element to the array list at a given position 
arrayList.addAll(Collection c) - adds all element from the specified collection to the end of the list, in the order that they are returned by the specified collection's iterator
arrayList.addAll(int index, Collection c) - used to append all the elements in the specified collection, starting at the specified position of the list
arrayList.clear() - used to remove all elements from this list. This has an O(n) time complexity
arrayList.get(int index) - gets an item from the array list 
arrayList.isEmpty() - returns true if the list is empty, otherwise false
arrayList.toArray() - return an array containing all of the elements in this list in the correct order
arrayList.indexOf(Object o) - it is used to return the index in this list of the first occurrence of the specified element, or -1 if the list does not contain this element. 
arrayList.remove(int index) - removes the element at a given index 
arrayList.removeAll(Collection c) - used to remove all the elements from a list that are contained in the specified collection. This has an O(n^2) time complexity as internally it loop through the arrayList and calls arrayList.contains(), which is O(n). 
arrayList.size() - returns the number of elements in the array list 
ArrayList.retainAll(Collection c) - used to retain all the elements in the list that are present in the specified collection. The time complexity is O(n^2) as it’s really just the reverse of arrayList.removeAll(). 
arrayList.contains(Object o) - return true if the list contains the specified element, false otherwise. This runs in O(n) time. 
arrayList.set(int index, E element) - used to replace the specified element in the list, present at the specified position 
Stack<DataType> stack = new Stack<>(); Note that is Java, stacks are resizable (they inherit from the Vector class in java which implements a growable array of objects). So a stack is a vector and it also can’t be full (it always just resizes when full). 
stack.empty() - returns true if nothing is on top of the stack, else it return false
stack.peek() - gets the top element but doesn’t remove it 
stack.pop() - removes and returns the top element of the stack. An exception is thrown if we call pop() when the invoking stack is empty.
stack.push(Object element) - pushes an element to the top of the stack
stack.search(Object element) - determines whether an object exists in the stack.  If the element is found, it returns the position of the element from the top of the stack. Else, it returns -1.

Example: 

import java.util.Stack;


class Main {
    public static void main(String[] args) {
        Stack<String> animals= new Stack<>();


        // Add elements to Stack
        animals.push("Dog");
        animals.push("Horse");
        animals.push("Cat");
        System.out.println("Stack: " + animals);


        // Search an element
        int position = animals.search("Horse");
        System.out.println("Position of Horse: " + position);
    }
}

Stack: [Dog, Horse, Cat]
Position of Horse: 2
stack.contains(Object o) - returns true if this vector contains the specified element 
stack.containsAll(Collection c) - returns true if this vector contains all the elements in the specified collection
stack.clear() - clears all elements from the stack
stack.get(int index) - gets the element at the specified position in this vector
Stack.indexOf(Object o) - returns the index of the first occurrence of the specified element in this vector, or -1 if this vector does not contain the element.
Stack.indexOf(Object o, int index) - returns the index of the first occurrence of the specified element in this vector, searching forwards from the index, or returns -1 if the element is not found.
Remove and set operations are the same as an array list (these are listed for simplicity) 
stack.setSize() - sets the size of this vector
stack.toArray() - returns an array containing all elements of this stack in the corresponding order
stack.size() - gets the number of elements in the stack
stack.capacity() - gets the the capacity of the stack
LinkedList linkedList = new LinkedList() or LinkedList linkedList = new LinkedList (Collection c). The second one will create a linked list with all of the elements of the given collection. A linked list in java is implemented as a doubly linked list. All the time complexities of Java's linked list are exactly as you'd expect for a typical linked list. 
The add(), add(int index, E e), set(), size(), contains(), get(), indexOf(), toArray(), addAll (Collection c), addAll (index, Collection c), toString() methods are identical to arrayList. 
linkedList.addFirst(E e) - adds the specified element to the beginning of the list
linkedList.addLast(E e) - adds the specified element to the end of the list 
linkedList.remove() - retrieves and removes the head (first element) of this list 
linkedList.remove(int index) - removes the element at the specified position in this list (O(n) time complexity)
linkedList.remove(Object o) - removes the first occurrence of the specified element from this list, if it is present (O(n) time complexity)
linkedList.removeFirst() - removes and returns the first element of this list 
linkedList.removeLast() - removes and returns the last element from this list 
linkedList.listIterator(int index) - Returns a list-iterator of the elements in this list (in proper sequence), starting at the specified position in the list.
Iterating over a linked list: 

LinkedList<E> list = new LinkedList<>(); 
ListIterator<E> listIter = list.listIterator(0);
while (listIter.hasNext()) {
    E element = listIter.next();
    ...
    // Remove the element last polled
    listIter.remove();
    // Inserts an element right before the last polled element
    listIter.add(new Element());
}

// note that iterator.remove() is O(1) for LinkedList with Iterator or ListIterator 
Iterator and ListIterator O(1) remove LinkedList: https://coderanch.com/t/617235/java/remove-operation-LinkedList-time-complexity

Iterator vs List Iterator 


https://stackoverflow.com/questions/10977992/difference-between-iterator-and-listiterator

Queue<Datatype> queue = new LinkedList<>(); You can also do the same thing for PriorityQueues as well. A linked list is used because of it's easy insertion and deletion and it's also more memory efficient as we don't need to preallocate memory for unused capacity (it's grows as needed). Note that LinkedList and PriorityQueue are not thread safe. 
queue.add(E e) - adds an element to the end of the queue
queue.offer() - adds an element to the end of the queue. This method is preferable to the add() method since this method doesn't throw an exception when the capacity of the container is full since it returns false. Note that in the case of no capacity restrictions, the contracts of add() and offer() display the same behavior. So the add and offer methods of LinkedList and ArrayDequeue won't have any behavior differences since both of those collections are unbounded. 
queue.peek() - gets the first element (beginning) of the queue without removing it. This returns Null if the queue is empty. When using ArrayBlocking queue there will be differences in the add() and offer() methods (so those methods will work exactly as described). This is again because the ArrayBlockingQueue has capacity restrictions. 
queue.poll() - removes and returns the beginning of the queue. It returns null if the queue is empty. 
queue. remove() - removes and returns the beginning of the queue. It throws NoSuchElementException when the queue is empty. 
queue.size() - gets the number of elements in the queue
queue.isEmpty() - returns true if the queue is empty, otherwise it returns false
To iterate over a queue you can convert it to an array and do so but a quicker way is to use an iterator like below. 

Queue<String> queue = new LinkedList<>();
Iterator<String> iterator = queue.iterator();
while (iterator.hasNext()) {
    System.out.println(iterator.next() + " ");
}

ArrayDequeue has the same add(), offer(), peek(), remove(), poll() methods as Queue and the same push(), pop and peek() as Stack. Creating a deque can be done like so: Deque<Datatype> queue  = new ArrayDeque<>();
arrayDeque.addFirst() - adds an element at the start of the deque and throws an exception when full
arrayDeque.addLast() - adds an element at the end of the deque and throws an exception when full
arrayDeque.offerFirst() - adds an element to the front of the queue and returns true if successfully added else false
arrayDeque.offerLast() - adds an element to the end of the queue and returns true if successfully added else false
arrayDeque.getFirst() - throws an exception if queue is empty
arrayDeque.getLast()
arrayDeque.peekFirst() - is used to retrieve or fetch the first element of the deque. The element retrieved does not get deleted or removed from the Queue instead the method just returns it. If no element is present in the deque, then Null is returned
arrayDeque.peekLast()
arrayDeque.removeFirst() - throws an exception if queue is empty
arrayDeque.removeLast()
arrayDeque.pollFirst() -  is used to retrieve or fetch and remove the first element of the deque. It returns null if the deque is empty 
arrayDeque.pollLast() -  is used to retrieve or fetch and remove the last element of the deque. It returns null if the deque is empty 
arrayDeque.push()
arrayDeque.pop()
PriorityQueue<Datatype> pq = new PriorityQueue<E>(); (This creates a min heap)
iterator.next() - returns the next element 
iterator.remove() - removes the last element returned by the iterator. Throws IllegalStateException if an attempt is made to call remove( ) that is not preceded by a call to next( ). Removes from the underlying collection the last element returned by this iterator (optional operation). This method can be called only once per call to next(). The behavior of an iterator is unspecified if the underlying collection is modified while the iteration is in progress in any way other than by calling this method.
PriorityQueue<Datatype> pq = new PriorityQueue<E>(Collections.reverseOrder()); (This creates a max heap)
PriorityQueue<Datatype> pq = new PriorityQueue<E>(Collection<E> c);
PriorityQueue<Datatype> pq = new PriorityQueue(int initialCapacity, Comparator<Datatype> comparator);
The add(), peek(), poll(), offer()and remove() methods are all the same as from the queue interface. The elements are sorted in ascending order (smallest to largest) by default. 
priorityQueue.remove(Object o) -  If there are multiple of objects then the first occurrence of the object is removed. 
You can iterate through a queue using an iterator or a for loop.

PriorityQueue<String> pq = new PriorityQueue<>();
pq.add("Geeks");
pq.add("For");
pq.add("Geeks");


Iterator iterator = pq.iterator();
while (iterator.hasNext()) {
    System.out.print(iterator.next() + " ");
 }
Things to know
Primitive types use (==) for comparison while wrapper classes (objects) use .equals() for comparison 
The Java for loop can only contain three different variables (unconfirmed, I got this from a Stack Overflow comment) and must only have one termination condition
All characters are separated by an empty string. Additionally empty String is present at the beginning and at the end of every string. (Likewise, every single set is a superset of an empty set.)

It's a longest prefix that starts from index 0 (in [“aca", “cba”], there is no longest common prefix since “a” doesn’t connect with a prefix starting from index 0)
The “break;”, breaks you out a switch, which saves time
“default:” in a switch will provide a case in case all other cases fail (there is no need for a “break;” inside of default)
In Java, all elements(primitive integer types byte short, int, long) are initialized to 0 by default. You can save the loop
You can use an else block to return a value from a method instead of returning it outside of an if else block (you normally need to do this if you’re using an if block or an else if block because a method must return a value if it’s return type isn’t void). This can make things a little neater. 
Tricks
You can get the last digit of an integer by doing (integer mod 10)
You can remove the last digit of an integer from a variable by doing (x = x / 10, assuming x is an integer). Likewise we can use this concept with the number 10 (or up to 18 (because the maximum number from two digits is 18 (9 + 9 = 18))) to get the carry in elementary addition. For example 8 + 4 = 12 / 10 = 1. The carry is always 1 or 0 and we can use this value next time to continue addition. 
We can get the number value of a char without converting the char to a String and passing it into Integer.parseInt(). Chars can be implicitly converted to an integer (ASCII) like so x = ‘0’. We can get the number as a string by doing: int x = intAsStringToConvert - ‘0’. For example, suppose we want to convert the string ‘9’ to an int whose value is 9. 

int x = ‘9’ - ‘0’
// x will be 9

What’s going on here? This returns the value of a number. If you convert '0' to an int, the value is 48, per the ASCII values. '9' = 57. If you subtract ‘9' from ‘0' you get 9.

To prevent accessing an element that doesn’t exist in anything (string, array, list, map, etc.) surround it with an if else block until certain conditions are met. By default, use dummy values like int x = 0; in the event that the condition fails, a dummy value can be used in a necessary calculation using the variable. In this way you can avoid exceptions without try catch blocks. Make sure that the dummy value has no effect on the calculation (you’ll likely use 0 or 1). 
You can create more flexible while loops by using multiple OR (||) conditions. For example:

while (x1 >= 0 || x2 >= 0 || carry > 0) { }

This makes it so that the loop only terminates when all the conditions are no longer true. This is excellent for when you need to loop through till all conditions are no longer satisfied. This is especially useful when used with the last trick (using dummy values and an if else statement that safely retrieves elements from a data structure till there's no more). 
Time complexity for looping over a 2d array: the time complexity will be O (n*m) where n the number of arrays which is the 1st dimension and m the max size of each internal array ie, the 2nd dimension
A common usage of an array is to represent the number of character occurrences like so:
String s = "example";
int[] count = new int[26]; // for the 26 letters of the alphabet 
for (char c : s.toCharArray()) {
    count[c - 'a']++;
}
This is a lot more simple than creating a hash map when you know that you know the number of keys you'll have. In the event you need to access your values, you don't need to "hash the key" like you would need to in a hash map since you know exactly where it is in memory (you're using an array). While hashing is fast, not needing to hash will save you time. We also only have a fixed size of keys and values so we don't need a data structure that automatically resizes itself, a fixed size data structure is more appropriate and simple. 

Java Boolean operators 

Underflow and Overflow 
Overflow and underflow happen when we assign a value that is out of range of the declared data type of the variable. 

If the (absolute) value is too big we call it overflow, the value is too small, we call it underflow. 

integer-wraparound - describes the behavior that happens when an integer underflows or overflows. If an integer variable underflows it will become the max value of an integer (2^31 - 1). The reverse is true if an integer variable overflows as it will become the minimum value of an integer (-2^31). Java does not throw an exception when an overflow occurs; which is why it can be hard to find errors resulting from an overflow. Nor can we directly access the overflow flag, which is available in most CPUs. 

Overflow and Underflow in Java: https://www.baeldung.com/java-overflow-underflow#:~:text=Simply%20put%2C%20overflow%20and%20underflow,small%2C%20we%20call%20it%20underflow.

Ways to handle overflow in Java: 

Use a different data type

Use a different data type like a long which is much larger than an integer. Although, variables of type long can also overflow. We can also use BigInteger which isn’t restricted, except by the amount of memory available to the JVM. 

Throw an exception 
Time Complexity
When determining time complexity with Big O notation, we drop the constant. So for example and algorithm with a time complexity of O(n/2) is just O(n). 

If a log has no base written, you should generally assume that the base is 10. 

When you think of log(x), think of dividing the number of times in half each time. Any base of log(x) like log10(x) is just called log(x). 
Common time complexities
https://www.geeksforgeeks.org/understanding-time-complexity-simple-examples/
Amortized Time Complexity

Amortized analysis is used for algorithms that have expensive operations that happen only rarely. It’s used commonly with data structures that have state that persists between operations. The basic idea is that some operation can alter the state so that the worst case cannot occur again for a long time, thus amortizing (reducing) its cost. 

Amortized time complexity: https://yourbasic.org/algorithms/amortized-time-complexity-analysis/

Big O Notation Cheat Sheet: https://www.bigocheatsheet.com

Best Concievable Runtime: https://leetcode.com/problems/3sum/discuss/919739/what-is-bcr
Complexity and Constants
Complexity analysis ignores constants. For example, O(10⋅N)=O(N)O(10 \cdot N) = O(N) O(10⋅N)=O(N). Even O(10000⋅N)=O(N)O(10000 \cdot N) = O(N) O(10000⋅N)=O(N). Sometimes the constants we're ignoring in the analysis are still having a big impact on the run-time in practice. 

Character to Integer Conversion - (there are 3 ways)

Implicit Type Casting 
Since char is a smaller data type compared to int, we don’t need to do explicitly type casting. A simple assignment of char value to an int variable would do the trick, compiler automatically converting the char into int. This is known as implicit type casting or type promotion. 

ex. 

Using Character.getNumericValue()

This can be used to convert a char to an int. It excepts a char as an argument and returns the equivalent int (ASCII) value after conversion 


Using Integer.parseInt() method 

Math
series - the sum of the terms of a sequence. For example, the series for the sequence 1, 3, 5, 7, 9, . . . , 131, 133 is the sum 1 + 3 + 5 + 7 + 9 + … + 131 + 133. 

sequence - a list of numbers set apart by commas, such as 1, 3, 5 ,7, …

arithmetic sequence - a sequence which has a constant difference between terms (like 1, 5, 9, 13, 17). The first term is a1, the common difference is d and the number of terms is n. 

Explicit Formula: a(n) = a1 + (n - 1)d  (we use n - 1 because d isn't used in the first term) 

Example 1: 3, 7, 11, 15, 19 has a1 = 3, d = 4 and n = 5. The explicit formula is a(n) = 3 + (n - 1) * 4 = 4n - 1

Example 2: 3, -2, -7, -12 has a1 = -3, d = -5 and n = 4. The explicit formula is a(n) = 3 + (n-1)(-5) = 8 - 5n. 

geometric sequence - has a constant ratio between terms (like 2, 6, 18, 54, 162 or 3, 1, 1/3, 1/9, 1/27). The first term is a1, the common ratio is r and the number of terms is n. 

Explicit formula: a(n) = a1*r^(n-1)

arithmetic series - a series such as 3 + 7 + 11 + 15 + ··· + 99 or 10 + 20 + 30 + ··· + 1000 which has a constant difference between terms. The first term is a1, the common difference is d, and the number of terms is n. The sum of an arithmetic series is found by multiplying the number of terms times the average of the first and last terms. 



3 + 7 + 11 + 15 + … + 99 has a1 = 3,  d = 4 and n = 25. 

Sum = 25 * (3 + 99) / 2 = 1275
Logarithms
Logarithms answer this question: How many of one number do we multiply to get another number? 

Example: How many 2s do we multiply to get 8? 

Answer: 2 * 2 * 2 = 8, so we had to multiply 3 of the 2s to get 8

So the logarithm is 3. 


The logarithm tells us what the exponent is. Sometimes a log is written without a base, like this: 

log(100)

This usually means that the base is really 10. It’s called a common logarithm. It’s how many times we need to use 10 in multiplication to get our desired number.

log(1000) = log10(1000) = 3

Logarithms can have decimals

All of our examples have used whole number logarithms (like 2 or 3) but logarithms can have decimal values like 2.5 or 6.081, etc. 

Example: log10(26) = 1.41497…

The logarithm is saying that 10^1.41497... = 26 (10 with an exponent of 1.41497 … equals 26) 

About logarithms: https://www.mathsisfun.com/algebra/logarithms.html

Natural Logarithms: Base “e”

Another base that is often used is e (Euler’s Number) which is about 2.71828. 

This is called a natural logarithm. On a calculator it’s the “ln” button. 

It’s how many times we need to use “e” in a multiplication, to get our desired number. 
Programming Concepts
Comparators 
public interface Comparator<T> - A comparison function, which imposes a total ordering on some collection of objects. Comparators can be passed to a sort method (such as Collections.sort or Arrays.sort) to allow precise control over the sort order. 

The Comparator interface defines two methods: compare() and equals(). 

public int compare (Object obj1, Object obj2) - compares its two arguments for order. Returns a negative integer, zero or a positive integer as the first argument is less than, equal to or greater than the second. Note that things with negative values after being compared with compareTo() will come before positive values after a sort.  

By overriding compare(), you can alter the way that objects are ordered. 

The compare() uses Timsort which is O(nlog(n)) (worst case). 

Timsort - a hybrid stable sorting algorithm, derived from merge sort and insertion sort, designed to perform well on many kinds of real-world data. It was implemented by Tim Peters in 2002 for use in Python. The algorithm finds subsequences of the data that are already ordered (runs) and uses them to sort the remainder more efficiently. This is done by merging runs until certain criteria are fulfilled.  Timsort has been Python's standard sorting algorithm since version 2.3. It is also used to sort arrays of non-primitive type in Java SE 7,[4] on the Android platform,[5] in GNU Octave,[6] on V8,[7] and Swift.[8]

More about Timsort: https://en.wikipedia.org/wiki/Timsort



boolean equals(Object obj) - obj is the object to be tested for equality. The method returns true if obj and the invoking object are both Comparator objects and use the same ordering. Otherwise, it returns false. 

Overriding equals() is unnecessary and most simple comparators will not do so. 



public void sort(List list, Comparator c): is used to sort the elements of list by the given comparator
compareTo()
The Java String compareTo() method is used for comparing two strings lexicographically. Each character of both of he strings is converted into a unicode value for comparison. If both the strings are equal then this method return 0, else it returns a positive or negative value. The result is positive if the first string is lexicographically greater than the second string, else the result would be negative. 

public int compareTo(String s) - the comparison is between string literals. For example string1.compareTo(string2) where string1 and string2 are String literals. 

public int compareTo(Object obj) - here the comparison is between a string and an object. For example string1.compareTo(“Just a String object”) where string1 is a literal and its value is compared with the string specified in the method argument.

compareTo() is case sensitive (if you want a version that isn’t use compareToIgnoreCase())

About compareTo() method: https://beginnersbook.com/2013/12/java-string-compareto-method-example/ 
Sorting
Stable sorting algorithms sort equal elements in the same order that they appear in the input. 

Not all algorithms are stable, e.g merge sort is stable. The Arrays.sort() interface is stable. 

Stability is mainly important when we have key value pairs with duplicate keys possible (like people’s names as keys and their details as values) and we wish to sort these objects by keys. 

Another definition: A sorting algorithm is said to be stable if two objects with equals keys appear in the same order in sorted output as they appear in the input array to be sorted. 

Arrays.sort() 
Arrays.sort(int[]) uses quick sort under the hood because it’s faster as stability doesn’t matter since if the integers are the same value but aren’t in the same order, it doesn’t matter. This isn’t necessarily true for object if you’re just comparing one attribute or more of the object (there may be one object which is different is some of way so if it isn’t in the same order then it won’t work.). So worst case is O(n^2). 

Arrays.sort(Object[]) uses Timsort under the hood because stability is needed so it’s O(nlog(n)). 

Arrays.sort() vs Collections.sort: Arrays.sort works for arrays which can be of primitive type also. Collections.sort() works for objects that are Collections like ArrayList, LinkedList, etc. 

Time Complexities of different sorting algorithms: https://www.interviewkickstart.com/learn/time-complexities-of-all-sorting-algorithms

Sorting a 2-d Array: https://stackoverflow.com/questions/15452429/java-arrays-sort-2d-array
Recursion
The process of a function calling itself directly or indirectly. Using a recursive algorithm, certain problems can be solved quite easily. Example of such problems are Towers of Hanoi (TOH), In-order/Preorder/Postorder Tree Traversals, DFS of a Graph, etc. 

What is the base condition in recursion? 

In a recursive program, the solution to the base case is provided and the solution of the bigger problem is expressed in terms of smaller problems. 

(Note factorial is only defined for non-negative integers)

int fact(int n) {
    if (n <= 1) {  // base case 
        return 1;
    }
    else {
        return n * fact(n - 1); 
    }
}

The idea is to represent the problem in terms of one or more smaller problems, add one or more base conditions that stop the recursion.

A StackOverflow error can occur in recursion if we never reach the base case. For example if n== 1 when fact(10) is called, it will call fact(9), fact(8) and so on but the number will never reach 100. So the memory will be exhausted by these functions on the stack, causing a stack overflow error. 

Direct vs Indirect Recursion
A function fun is called direct recursive if it calls the same function fun. A function fun is called indirect recursive if it calls another function say fun_new and fun_new calls fun directly or indirectly. The difference is illustrated below. 

// An example of direct recursion
void directRecFun()
{
    // Some code....

    directRecFun();

    // Some code...
}

// An example of indirect recursion
void indirectRecFun1()
{
    // Some code...

    indirectRecFun2();

    // Some code...
}void indirectRecFun2()
{
    // Some code...

    indirectRecFun1();

    // Some code...
}

How memory is allocated to different function calls in recursion?
When any function is called from main(), the memory is allocated to it on the stack. A recursive function calls itself, the memory for a called function is allocated on top of memory allocated to a calling function and a different copy of local variables is created for each function call. When the base case is reached, the function returns its value to the function by whom it is called and memory is de-allocated and the process continues. 

Every recursive program can be written iteratively and the reverse is true. The recursive program has greater space requirements than the iterative program as all functions will remain in the stack until the base case is reached. It also has greater time requirements because of there function calls and returns overhead. 

What are the advantages of recursive programming over iterative programming? 
Recursion provides a clean and simple way to write code. Some problems are inherently recursive like tree traversals, Tower of Hanoi, etc. For such problems, it is preferred to write recursive code. Recursion is an “elegant” solution. We can write such code iteratively, with the help of a stack data structure. For example refer Inorder Tree Traversal without Recursion, Iterative Tower of Hanoi.
Time and Space Complexity
💡
The space complexity of a recursive algorithm is proportional to the maximum depth of the recursion tree generated.

For example: If each function call of a recursive algorithm takes O(m) space and if the maximum depth of the recursion tree is n then the space complexity of the recursive algorithm would be O(nm). 

Source: https://www.ideserve.co.in/learn/time-and-space-complexity-of-recursive-algorithms#:~:text=To%20conclude%2C%20space%20complexity%20of,would%20be%20O(nm).
Pass by Reference vs Pass by Value
Pass by Reference vs Pass by Value: 

When a function is called, the arguments can be passed by value or passed by a reference. 

callee - the function being called by another function 
caller - the function calling another function

actual parameters - the values passed in the function call

formal parameters - the values being received by the function (when it is called) are called the formal parameters


pass by value - when a parameter is passed by reference, the caller and the callee use the same variable for the parameter. If the callee modifies the parameter variable, the effect is visible to the caller's variable.

pass by reference - when a parameter is passed by value, the caller and callee have two independent variables with the same value. If the callee modifies the parameter variable, the effect is not visible to the caller.

Another way to put it is that in pass by value we are passing a “value” (actually a copy of a variable) meanwhile in pass by referencing we are passing in a “variable" (a reference, which we can modify). 
equals() and hashCode()
The purpose of the hashCode() method is to provide a numeric representation of an object's contents to an alternative mechanism to provide an alternative mechanism to loosely define it. 

By default hashCode() returns an integer that represents the internal memory address of the object. 

Two objects that are logically equivalent should produce the same hash (although keep in mind that collisions can still happen). 

equals() comes into picture only if hash are same for objects like when a collision occurs. 
Note: Equal objects must produce the same hash code as long as they are equal, however unequal objects need not produce distinct hash codes.

Basically we use hashCode() to optimize performance when comparing objects. 

The equals method compares the fields of an object 

About the containsKey() method: 


Implementing a hashcode() method: 

https://stackoverflow.com/questions/113511/best-implementation-for-hashcode-method-for-a-collection

Source Code for a general purpose hashCode() implementation (this implementation is good for nearly all cases): https://github.com/ciscorucinski/HashcodeAndEqual/blob/master/src/io/github/ciscorucinski/hashcodeandequal/MyType.java

Source: https://www.geeksforgeeks.org/equals-hashcode-methods-java/

More about hashCode() vs equals(): https://www.infoworld.com/article/3305792/comparing-java-objects-with-equals-and-hashcode.html
Memoization
Memoization is an optimization technique used to primarily speed up programs by storing the results of expensive functions calls and returning the cached result when the same input occurs again. A hash map is commonly used in memoization. Note that memoize is always top-down (ignore Leetcode).

It’s a common strategy for dynamic programming problems, which are problems where the solution is composed of solutions to the same problem with smaller inputs (like the fibonacci problem). The other common strategy for dynamic programming problems is going bottom up, which is usually cleaner and often more efficient. 

About memoization: https://www.interviewcake.com/concept/java/memoization\
Bottom Up
Going bottom up is a way to avoid recursion, saving the memory cost that recursion incurs when it builds the call stack. 

A bottom-up algorithm “starts from the beginning” while a recursive algorithm often “starts from the end and works backwards”. 

For example, if we wanted to multiply all the numbers in the range 1..n1..n, we could use this cute, top-down, recursive one-liner:
def product_1_to_n(n):
		# We assume n >= 1

return n * product_1_to_n(n - 1) if n > 1 else 1

This approach has a problem: it builds up a call stack of size O(n), which makes our total memory cost O(n). This makes it vulnerable to a stack overflow error, where the call stack gets too big and runs out of space. 

To avoid this, we can instead go bottom-up: 
def product_1_to_n(n):

    # We assume n >= 1

    result = 1

    for num in range(1, n + 1):

        result *= num

    return result
  
This approach uses O(1) space O(n) time). 
Top Down
Top Down is when we start from the end and work our way backwards to the beginning. This is usually used in recursive or memoized solutions (which use recursion themselves but in a smarter way). 


Top Down - Recursion, Memoization 
Bottom Up - Dynamic Programming 
Dynamic Programming
Dynamic Programming (DP) is a programming technique for solving an optimization problem by breaking it down into simpler subproblems and using the fact that the optimal solution to the overall problem depends on the optimal solution to its subproblems. 

It’s mainly an optimization over plain recursion. Whenever we see a recursive solution that has repeated calls for the same inputs, we can optimize it using dynamic programming. The idea of dynamic programming is to store the results of the subproblems so we don’t re-compute them later. 

Dynamic programming is tricky because we need to identify ways to calculate the sub problems and figure out how they interact with each other to create the overall optimal problem. Every problem has different ways that the sub problems interact with each other to come to the optimal overall problem. 

Although once we do see the sub problems and how they relate to each other, it becomes very straightforward. 

About Dynamic Programming: https://www.programiz.com/dsa/dynamic-programming
Greedy
A greedy algorithm is an algorithmic paradigm that builds a solution piece by piece, always choosing the next piece that offers the most obvious and immediate benefit. In a greedy algorithm we make whatever choice seems better at the moment in hope that it will lead to the globally optimal solution. 

In dynamic programming, we make a decision at each step considering the current problem and the solution to the previously solved sub problem to calculate the optimal solution. 

Note that a greedy approach doesn’t guarantee that we will arrive at the global optimal solution while in dynamic programming we will always arrive at the global optimal solution as it considers all possible cases and choses the best. 

Also note that in the greedy approach we never look back or revise previous choices. 

A greedy approach isn’t necessarily better than a dynamic programming approach as it depends on the problem, you’re trying to solve. 