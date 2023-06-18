#pragma once

#include <iostream>
#include <string>

using namespace std;

constexpr int ASCII_OFFSET = 48;

class Leaf {
public:
	Leaf *left, *right, *next = NULL;
	string data;

	Leaf() {
		left = NULL;
		right = NULL;
	}

	Leaf(string data) {
		this->data = data;
		this->left = NULL;
		this->right = NULL;
	}

	friend class Stack;
	friend class ExpressionTree;
};

class Stack { // holds leaf nodes
	Leaf* head = NULL;
public:
	void push(Leaf*);
	Leaf* pop();
	friend class ExpressionTree;
};

class ExpressionTree {
public:
	void in_order(Leaf* x) {
		if (x == NULL)
			return;
		else {
			in_order(x->left);
			cout << x->data << " ";
			in_order(x->right);
		}
	}

	int to_integer(string s) {
		// util function to convert string to int
		int num = 0;
		if (s[0] != '-') {
			for (int substr : s)
				num = num * 10 + (substr - ASCII_OFFSET); // ASCII constant
		}
		else {
			string sliced = s.substr(s.size() - 1);
			for (int substr : sliced) {
				num = num * 10 + (substr - ASCII_OFFSET); // ASCII constant
			}
			num = num * -1;
		}

		return num;
	}

	int evaluate(Leaf* x) {
		if (x == NULL)
			return 0;

		if (!x->left && !x->right) // leaf node
			return to_integer(x->data);

		int l_val = evaluate(x->left);
		int r_val = evaluate(x->right);

		string op_string = x->data;
		char op = op_string[0];
		if (op == '+')
			return l_val + r_val;
		if (op == '-')
			return l_val - r_val;
		if (op == '*')
			return l_val * r_val;
		if (op == '/')
			return l_val / r_val;
		if (op == '*')
			return l_val ^ r_val;
	}
};

void Stack::push(Leaf* x) {
	if (head == NULL)
		head = x;
	else {
		x->next = head;
		head = x;
	}
}

Leaf* Stack::pop() {
	Leaf* p = head;
	head = head->next;
	return p;
}

