# Data Structures and Algorithms

## Short-List

1. Linked List
2. Binary Trees + Hash Tables
3. Graphs + Graph Traversal
4. Search Algorithms
5. Sort Algorithms
6. Info Retrieval

***If you have limited time and need to focus on the most essential data structures and algorithms, here's a distilled list of what you should prioritize:***

## Data Structures

### Arrays and Strings
Must-Know Topics: Traversal, Two-Pointer Technique.
Key Problems: Two Sum, Reverse a String, Sliding Window (e.g., Longest Substring Without Repeating Characters).

### Linked Lists
Must-Know Topics: Singly Linked List, Fast and Slow Pointer.
Key Problems: Reverse a Linked List, Detect Cycle in a Linked List.

### Hash Maps/Sets
Must-Know Topics: Insert, Search, and Delete operations.
Key Problems: Two Sum (Hash Map), Longest Consecutive Sequence.

### Stacks and Queues
Must-Know Topics: Basic operations, Stack for Parentheses Matching.
Key Problems: Valid Parentheses, Implement Queue using Stacks.

## Algorithms

### Sorting and Searching
Must-Know Topics: Binary Search, Sorting (Quick Sort, Merge Sort).
Key Problems: Search in Rotated Sorted Array, Merge Intervals.

### Dynamic Programming (DP)
Must-Know Topics: Memoization, Bottom-Up DP.
Key Problems: Fibonacci Sequence, 0/1 Knapsack, Longest Increasing Subsequence.

### Recursion/Backtracking
Must-Know Topics: Base Case and Recursive Case, Backtracking.
Key Problems: Generate Parentheses, Subsets, Permutations.
## Core Concepts

### Tree Traversals
Must-Know Topics: Binary Tree Inorder, Preorder, Postorder.
Key Problems: Binary Tree Level Order Traversal, Lowest Common Ancestor.

### Graph Traversals
Must-Know Topics: BFS, DFS.
Key Problems: Number of Islands, Graph Cycle Detection.

## High-Yield Strategy:
1. Focus on Arrays, Strings, and Hash Maps/Sets: These are foundational and are the most common topics in coding interviews.
2. Learn Binary Search and Sorting: These are critical and can be combined with other data structures to solve more complex problems.
3. Get Comfortable with Recursion and DP: Even basic understanding can help you tackle a wide range of problems.
4. Practice Tree and Graph Traversals: These are common in interviews, especially for roles requiring more algorithmic depth.

## Resources for Quick Review:
1. LeetCode Easy/Medium Problems: Start with arrays and strings, then move to linked lists and hash maps.
2. Top Coder or Codeforces Problems: Focus on problems tagged with "Dynamic Programming" and "Greedy."
3. Cracking the Coding Interview (Book): Skim through the most relevant sections, particularly on these topics.

***By concentrating on these essentials, you can maximize your preparation in a limited timeframe.***


**Coding Interview Tips: https://thenextweb.com/syndication/2020/11/03/twitter-engineer-shares-5-tips-on-how-to-ace-coding-interviews/**

**Common Coding Interview Patterns: https://hackernoon.com/14-patterns-to-ace-any-coding-interview-question-c5bb3357f6ed**

---
## Tips
Always have hash tables at the back of your mind for solving coding problems.
If the type of time complexity isn’t given, always assume that the interviewer wants you to give the worst case 
Whenever we’re trying to optimize an algorithm, we think of the bottlenecks, the unnecessary work and the duplicate work (this is from cracking the coding interview). The abbreviation: BUD
When you have an array problem, think of ways you can solve it in linear time
When trying to solve recursive problems think about what the base case is (especially when the first base case happens) and what happens when the recursive call is returned (so when the recursion begins unraveling) and how that affects the next (especially the second to last recursive call)
Think carefully about the space complexity for tree problems 
Use ArrayDequeue over Stack as it's more abstract (it's an interface vs. a class like with Stack), faster and more restricted, working like an actual stack since it doesn't let you access individual elements like the Stack class, which implements a Vector that allows that . Also use ArrayDequeue over LinkedList as well. 
Easy problems often require you to know one “thing” or a small number of observations, ideas and facts. Easy problems often have straightforward problem statements (easy to understand what you have to do / return), although may require a simpler “trick”. Medium problems tend to require you to think more about data structures and algorithms you’re going to use far more and require to connect multiple observations to the appropriate data structures and algorithms. 

## Studying Strategy 
Solve easy medium hard in 3:6:1 or 3:5:2 ratio 
Problem Solving Strategy
Make sure you understand the question correctly. Validate your assumptions by thinking of some different input and outputs.
Think about different techniques you can use (specific algorithms and data structures). Do you think a problem can be solved in a given time complexity? Explain why or why not. If you can’t think of an optimal solution, may be a good idea to ask for a hint if you’re stuck or just give the brute force solution. 
Consider constraints. Are there any conditions that allow us to return out of our method in O(1)? If so mention those and implement it. Will show attention to detail. 
Move onto write code. Make sure you understand the time complexity of the solution.
You don't need to think of everything before you start coding. If you get stuck trying to understand your approach for too long just starting coding and figuring it out as you go along. You always want to write a good amount of code. A working non-optimal solution is better than a non-working more optimal one. 
---
## Suggested Study from Online Source
Data Structures: Array, Linked List, Hash Map, Graph, Tree, Stack, Queue, Heap, Binary Search Tree
Algorithms: Binary Search, Breadth-first Search, Depth-first Search
Other Common Concepts For Coding Interviews: Time & Space Complexity, Dynamic Programming, Greedy, Memoization, Recursion, Quick Sort, Amortized Analysis
Suggested As Well: Sliding window, backtracking and topological
Advanced data structures like trie, disjoint set (union find) sort.

Leetcode Medium is probably the most difficult.

---
## Thorough Study-Guide

### Coding & Algorithms
#### The Basics
How do you use conditions (if, else) in programming?
What are the different types of loops (for loops, while loops), and how are they used?
How do dictionaries work, and what are their uses?
How do you perform operations on slices, lists, or arrays?
How do you handle string and array operations (split, contains, length, regular expressions)?
How do you write and interpret pseudocode?

#### Big O Notation
How do you evaluate time and space complexity using Big O notation?

#### Data Structures
What are dictionaries (hash tables), and how are they implemented?
How do arrays and stacks function, and what are their uses?
How do SQL tables and Bigtable structures work?

#### Sorting
How does quicksort work, and what are its advantages?
How does merge sort work, and when is it used?

#### Searching
What are the differences between binary and linear search algorithms?

#### Regular Expressions
What is the basic syntax of regular expressions, and how are they used?
How do regular expressions impact performance (e.g., O(n) vs. O(n!) complexity)?

#### Recursion
What is recursion, and why is it rarely used in practice?

#### Python
How do list comprehensions and generators work in Python?
What are iterators and generators, and how are they used in Python?
How do slicing operations work in Python (e.g., [start:stop])?
What are the key differences between Python and other programming languages like C and Java?
What are some common functions in Python that you should be familiar with, and what are their uses?

#### Data Structures Complete List
Strings
StringBuilder 
Arrays
Sorting a 2d Array
Hash Table & Hash Map
Collisions
Hashing 
Time Complexity 
Hash Map vs Hash Table
HashSet 
LinkedHashMap 
LinkedHashSet
Linked List 
Linked List Applications
Traversing a linked list: 
Types of Linked List 
ArrayList
Time Complexity of ArrayList operations
Stack
Queue 
Basic Operations of a Queue 
Working of Queue 
Limitation of Queue 
Applications of Queue Data Structure
Types of Queues
Time Complexity 
About ArrayDequeue vs vs Dequeue (Linked List): 
Trees
Tree Terminology
Types of Binary Tree: 
Binary Search Tree (BST) 
Tries
Uses of Traversals
Graphs
Relationships between Graphs and Trees 
Standard definition of a graph
Better definition of a graph 
Heap
Heap Operations 
Heap Applications
Priority Queue (Heap in Java)
Union Find
Java Implementation 
Primitive Recursive Function 
Algorithms
Breath First Search (BFS) and Depth First Search (DFS)
Linear Search 
Binary Search 
Sorting
Time Sort
Sliding Window
Topological Sort
Backtracking
Useful Java Methods
Things to know
Tricks
Java Boolean operators 
Underflow and Overflow 
Time Complexity
Common time complexities
Amortized Time Complexity
Complexity and Constants
Math
Logarithms
Natural Logarithms: Base “e”
Programming Concepts
Comparators 
compareTo()
Sorting
Arrays.sort() 
Recursion
Direct vs Indirect Recursion
How memory is allocated to different function calls in recursion?
What are the advantages of recursive programming over iterative programming? 
Time and Space Complexity
Pass by Reference vs Pass by Value
equals() and hashCode()
Memoization
Bottom Up
Top Down
Dynamic Programming
Greedy

---





