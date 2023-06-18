#include <string>
#include <vector>

#include "ll.hpp"
#include "tree.hpp"
#include "utils.hpp"

using namespace std;

Stack s;
ExpressionTree et;
Leaf* x, * y, * z;
LinkedList ll;

Leaf* insert_into_expression_tree(vector<string> string_vec) {
	for (string sub_str : string_vec) {
		if (sub_str.size() == 1) { // operator or single number
			char test = sub_str[0];
			if (test == '+' || test == '-' || test == '*' || test == '/' || test == '^') {
				// if operator, pop 2 previous elements and make binary tree
				z = new Leaf(sub_str);
				x = s.pop();
				y = s.pop();
				z->left = y;
				z->right = x;
				s.push(z);
			}
			else {
				// push operand onto stack
				z = new Leaf(sub_str);
				s.push(z);
			}
		}
		else {
			// push operand onto stack
			z = new Leaf(sub_str);
			s.push(z); 
		}
	}

	return z;
}

//void alternating_ll_append(string to_insert) {
//	enumerate(to_insert, [](size_t idx, char chr)
//		{
//			cout << "idx: " << idx << " ";
//			cout << "chr: " << chr << endl;
//
//			if (idx % 2 == 0)
//				ll.append_node_iterative(chr);
//			else
//				ll.append_node_recursive(chr);
//		});
//}

int check_flag(string entered_flag) {
	vector<char> accumulated = {};

	vector<string> vec_0 = { "2", "2", "*", "2", "*", "7", "+", "2", "2", "*", "2", "*", "+", "2", "2", "*", "2", "*", "+", "7", "+", "2", "2", "*", "3", "*", "+", "7", "+", "2", "2", "*", "2", "*", "+", "2", "5", "*", "+", "2", "2", "*", "2", "*", "+" };
	Leaf* root = insert_into_expression_tree(vec_0);
	int result = et.evaluate(root);
	accumulated.push_back(result);

	vector<string> vec_1 = { "7", "2", "3", "*", "+", "2", "2", "*", "+", "2", "3", "*", "+", "3", "3", "*", "+", "2", "2", "*", "+", "2", "3", "*", "+", "2", "3", "*", "+", "3", "+", "2", "3", "*", "3", "*", "+" };
	root = insert_into_expression_tree(vec_1);
	result = et.evaluate(root);
	accumulated.push_back(result);

	vector<string> vec_2 = { "2", "2", "*", "2", "*", "2", "2", "*", "2", "*", "+", "2", "3", "*", "+", "5", "+", "2", "2", "*", "2", "*", "+", "2", "3", "*", "+", "2", "2", "*", "+", "2", "3", "*", "+", "5", "+", "13", "+" };
	root = insert_into_expression_tree(vec_2);
	result = et.evaluate(root);
	accumulated.push_back(result);

	vector<string> vec_3 = { "17", "2", "5", "*", "+", "7", "+", "2", "2", "*", "2", "*", "+", "13", "+", "2", "2", "*", "3", "*", "+", "13", "+", "2", "2", "*", "2", "*", "2", "*", "+", "3", "3", "*", "+", "2", "3", "*", "3", "*", "+" };
	root = insert_into_expression_tree(vec_3);
	result = et.evaluate(root);
	accumulated.push_back(result);

	vector<string> vec_4 = { "3", "3", "+", "5", "+", "5", "+", "7", "+", "7", "+", "3", "+", "2", "2", "*", "+", "3", "+", "13", "+" };
	root = insert_into_expression_tree(vec_4);
	result = et.evaluate(root);
	accumulated.push_back(result);

	vector<string> vec_5 = { "11", "3", "3", "*", "+", "2", "5", "*", "+", "2", "2", "*", "2", "*", "2", "*", "+", "7", "+", "2", "2", "*", "2", "*", "2", "*", "+", "13", "+", "3", "5", "*", "+", "2", "2", "*", "2", "*", "+", "2", "7", "*", "+" };
	root = insert_into_expression_tree(vec_5);
	result = et.evaluate(root);
	accumulated.push_back(result);

	vector<string> vec_6 = { "2", "3", "*", "2", "2", "*", "+", "3", "+", "2", "+", "2", "2", "*", "+", "2", "2", "*", "+", "2", "2", "*", "+", "2", "3", "*", "+", "2", "3", "*", "+", "2", "5", "*", "+" };
	root = insert_into_expression_tree(vec_6);
	result = et.evaluate(root);
	accumulated.push_back(result);

	vector<string> vec_7 = { "2", "5", "*", "2", "5", "*", "+", "2", "3", "*", "+", "2", "2", "*", "2", "*", "+", "2", "3", "*", "+", "11", "+", "11", "+", "2", "2", "*", "3", "*", "+", "2", "7", "*", "+", "2", "11", "*", "+" };
	root = insert_into_expression_tree(vec_7);
	result = et.evaluate(root);
	accumulated.push_back(result);

	vector<string> vec_8 = { "2", "2", "*", "2", "2", "*", "+", "3", "+", "5", "+", "2", "3", "*", "+", "2", "2", "*", "+", "2", "3", "*", "+", "2", "2", "*", "+", "2", "3", "*", "+", "2", "2", "*", "3", "*", "+" };
	root = insert_into_expression_tree(vec_8);
	result = et.evaluate(root);
	accumulated.push_back(result);

	vector<string> vec_9 = { "2", "2", "*", "2", "2", "*", "+", "2", "2", "*", "+", "2", "+", "2", "+", "2", "2", "*", "+", "3", "+", "2", "+", "3", "+", "3", "7", "*", "+" };
	root = insert_into_expression_tree(vec_9);
	result = et.evaluate(root);
	accumulated.push_back(result);

	vector<string> vec_10 = { "2", "2", "*", "3", "*", "13", "+", "2", "3", "*", "+", "3", "3", "*", "+", "2", "2", "*", "2", "*", "+", "3", "5", "*", "+", "2", "2", "*", "3", "*", "+", "2", "5", "*", "+", "2", "5", "*", "+", "3", "5", "*", "+" };
	root = insert_into_expression_tree(vec_10);
	result = et.evaluate(root);
	accumulated.push_back(result);

	vector<string> vec_11 = { "7", "3", "+", "2", "2", "*", "+", "7", "+", "2", "3", "*", "+", "5", "+", "2", "2", "*", "+", "3", "+", "5", "+", "2", "5", "*", "+" };
	root = insert_into_expression_tree(vec_11);
	result = et.evaluate(root);
	accumulated.push_back(result);

	vector<string> vec_12 = { "2", "2", "*", "2", "*", "2", "2", "*", "3", "*", "+", "11", "+", "2", "3", "*", "+", "2", "3", "*", "+", "2", "2", "*", "3", "*", "+", "2", "5", "*", "+", "2", "2", "*", "3", "*", "+", "2", "3", "*", "+", "2", "2", "*", "3", "*", "+" };
	root = insert_into_expression_tree(vec_12);
	result = et.evaluate(root);
	accumulated.push_back(result);

	vector<string> vec_13 = { "5", "2", "2", "*", "+", "3", "+", "7", "+", "5", "+", "5", "+", "5", "+", "2", "2", "*", "+", "5", "+", "2", "2", "*", "3", "*", "+" };
	root = insert_into_expression_tree(vec_13);
	result = et.evaluate(root);
	accumulated.push_back(result);

	vector<string> vec_14 = { "2", "2", "*", "3", "*", "2", "2", "*", "2", "*", "+", "3", "5", "*", "+", "2", "5", "*", "+", "2", "7", "*", "+", "2", "5", "*", "+", "5", "+", "2", "7", "*", "+", "2", "7", "*", "+", "2", "+" };
	root = insert_into_expression_tree(vec_14);
	result = et.evaluate(root);
	accumulated.push_back(result);

	vector<string> vec_15 = { "11", "3", "5", "*", "+", "2", "7", "*", "+", "3", "5", "*", "+", "2", "3", "*", "+", "2", "3", "*", "+", "2", "7", "*", "+", "2", "5", "*", "+", "2", "2", "*", "2", "*", "2", "*", "+", "7", "+" };
	root = insert_into_expression_tree(vec_15);
	result = et.evaluate(root);
	accumulated.push_back(result);

	vector<string> vec_16 = { "5", "5", "+", "2", "+", "5", "+", "2", "3", "*", "+", "2", "3", "*", "+", "2", "3", "*", "+", "2", "2", "*", "+", "2", "2", "*", "+", "5", "+" };
	root = insert_into_expression_tree(vec_16);
	result = et.evaluate(root);
	accumulated.push_back(result);

	vector<string> vec_17 = { "11", "3", "5", "*", "+", "2", "7", "*", "+", "2", "7", "*", "+", "2", "5", "*", "+", "2", "2", "*", "2", "*", "+", "2", "2", "*", "2", "*", "2", "*", "+", "7", "+", "2", "7", "*", "+", "2", "2", "*", "2", "*", "+" };
	root = insert_into_expression_tree(vec_17);
	result = et.evaluate(root);
	accumulated.push_back(result);

	vector<string> vec_18 = { "3", "3", "+", "5", "+", "2", "3", "*", "+", "7", "+", "2", "3", "*", "+", "7", "+", "2", "2", "*", "+", "3", "+", "2", "5", "*", "+" };
	root = insert_into_expression_tree(vec_18);
	result = et.evaluate(root);
	accumulated.push_back(result);

	vector<string> vec_19 = { "11", "5", "+", "2", "5", "*", "+", "2", "2", "*", "2", "*", "+", "2", "5", "*", "+", "13", "+", "13", "+", "2", "2", "*", "2", "*", "+", "2", "7", "*", "+", "2", "2", "*", "3", "*", "+" };
	root = insert_into_expression_tree(vec_19);
	result = et.evaluate(root);
	accumulated.push_back(result);

	vector<string> vec_20 = { "2", "2", "*", "2", "*", "2", "2", "*", "3", "*", "+", "11", "+", "2", "3", "*", "+", "2", "3", "*", "+", "2", "2", "*", "3", "*", "+", "2", "5", "*", "+", "2", "2", "*", "3", "*", "+", "2", "3", "*", "+", "2", "2", "*", "3", "*", "+" };
	root = insert_into_expression_tree(vec_20);
	result = et.evaluate(root);
	accumulated.push_back(result);

	vector<string> vec_21 = { "2", "2", "*", "2", "3", "*", "+", "5", "+", "5", "+", "5", "+", "5", "+", "5", "+", "7", "+", "3", "+", "2", "5", "*", "+" };
	root = insert_into_expression_tree(vec_21);
	result = et.evaluate(root);
	accumulated.push_back(result);

	vector<string> vec_22 = { "3", "3", "*", "2", "2", "*", "2", "*", "+", "2", "2", "*", "2", "*", "+", "5", "+", "2", "3", "*", "+", "3", "5", "*", "+", "2", "7", "*", "+", "2", "3", "*", "+", "2", "5", "*", "+", "23", "+" };
	root = insert_into_expression_tree(vec_22);
	result = et.evaluate(root);
	accumulated.push_back(result);

	vector<string> vec_23 = { "2", "3", "*", "2", "2", "*", "+", "7", "+", "5", "+", "2", "2", "*", "+", "2", "2", "*", "+", "2", "3", "*", "+", "2", "2", "*", "+", "5", "+", "2", "3", "*", "+" };
	root = insert_into_expression_tree(vec_23);
	result = et.evaluate(root);
	accumulated.push_back(result);

	vector<string> vec_24 = { "2", "5", "*", "7", "+", "11", "+", "5", "+", "2", "2", "*", "2", "*", "+", "13", "+", "2", "2", "*", "3", "*", "+", "3", "3", "*", "+", "2", "2", "*", "3", "*", "+", "2", "2", "*", "2", "*", "+" };
	root = insert_into_expression_tree(vec_24);
	result = et.evaluate(root);
	accumulated.push_back(result);

	vector<string> vec_25 = { "3", "3", "+", "3", "+", "3", "+", "2", "3", "*", "+", "5", "+", "5", "+", "5", "+", "7", "+", "3", "5", "*", "+" };
	root = insert_into_expression_tree(vec_25);
	result = et.evaluate(root);
	accumulated.push_back(result);

	vector<string> vec_26 = { "2", "2", "*", "3", "*", "13", "+", "11", "+", "11", "+", "2", "2", "*", "2", "*", "2", "*", "+", "11", "+", "2", "2", "*", "2", "*", "+", "3", "3", "*", "+", "13", "+", "2", "5", "*", "+" };
	root = insert_into_expression_tree(vec_26);
	result = et.evaluate(root);
	accumulated.push_back(result);

	vector<string> vec_27 = { "5", "5", "+", "5", "+", "5", "+", "7", "+", "2", "2", "*", "+", "3", "+", "3", "+", "5", "+", "3", "3", "*", "+" };
	root = insert_into_expression_tree(vec_27);
	result = et.evaluate(root);
	accumulated.push_back(result);

	vector<string> vec_28 = { "3", "5", "+", "5", "+", "2", "2", "*", "+", "5", "+", "3", "+", "5", "+", "7", "+", "5", "+", "3", "3", "*", "+" };
	root = insert_into_expression_tree(vec_28);
	result = et.evaluate(root);
	accumulated.push_back(result);

	vector<string> vec_29 = { "2", "2", "*", "5", "+", "3", "+", "5", "+", "3", "+", "3", "+", "5", "+", "3", "+", "5", "+", "17", "+" };
	root = insert_into_expression_tree(vec_29);
	result = et.evaluate(root);
	accumulated.push_back(result);

	vector<string> vec_30 = { "13", "5", "+", "2", "3", "*", "+", "2", "2", "*", "2", "*", "+", "3", "3", "*", "+", "2", "3", "*", "+", "3", "3", "*", "+", "2", "3", "*", "+", "2", "2", "*", "3", "*", "+", "3", "7", "*", "+" };
	root = insert_into_expression_tree(vec_30);
	result = et.evaluate(root);
	accumulated.push_back(result);

	vector<string> vec_31 = { "5", "2", "3", "*", "+", "7", "+", "2", "2", "*", "+", "3", "+", "7", "+", "5", "+", "2", "2", "*", "+", "5", "+", "7", "+" };
	root = insert_into_expression_tree(vec_31);
	result = et.evaluate(root);
	accumulated.push_back(result);

	vector<string> vec_32 = { "2", "3", "*", "2", "3", "*", "+", "2", "2", "*", "+", "3", "+", "3", "+", "3", "+", "2", "2", "*", "+", "3", "+", "2", "2", "*", "+", "13", "+" };
	root = insert_into_expression_tree(vec_32);
	result = et.evaluate(root);
	accumulated.push_back(result);

	vector<string> vec_33 = { "2", "2", "*", "3", "*", "2", "2", "*", "2", "*", "+", "3", "3", "*", "+", "2", "2", "*", "2", "*", "+", "13", "+", "3", "5", "*", "+", "11", "+", "2", "2", "*", "2", "*", "+", "13", "+", "2", "2", "*", "+" };
	root = insert_into_expression_tree(vec_33);
	result = et.evaluate(root);
	accumulated.push_back(result);

	vector<string> vec_34 = { "5", "5", "+", "7", "+", "7", "+", "3", "+", "2", "2", "*", "+", "7", "+", "2", "2", "*", "+", "7", "+", "2", "3", "*", "+" };
	root = insert_into_expression_tree(vec_34);
	result = et.evaluate(root);
	accumulated.push_back(result);

	vector<string> vec_35 = { "3", "7", "+", "7", "+", "5", "+", "5", "+", "5", "+", "2", "2", "*", "+", "2", "2", "*", "+", "7", "+", "3", "+" };
	root = insert_into_expression_tree(vec_35);
	result = et.evaluate(root);
	accumulated.push_back(result);

	vector<string> vec_36 = { "3", "3", "*", "2", "7", "*", "+", "7", "+", "7", "+", "2", "2", "*", "3", "*", "+", "2", "2", "*", "2", "*", "+", "7", "+", "5", "+", "13", "+", "19", "+" };
	root = insert_into_expression_tree(vec_36);
	result = et.evaluate(root);
	accumulated.push_back(result);

	vector<string> vec_37 = { "2", "3", "*", "5", "+", "3", "+", "5", "+", "5", "+", "2", "3", "*", "+", "5", "+", "3", "+", "7", "+", "2", "5", "*", "+" };
	root = insert_into_expression_tree(vec_37);
	result = et.evaluate(root);
	accumulated.push_back(result);

	vector<string> vec_38 = { "13", "5", "+", "2", "2", "*", "2", "*", "+", "3", "3", "*", "+", "2", "3", "*", "+", "3", "3", "*", "+", "2", "2", "*", "3", "*", "+", "7", "+", "3", "3", "*", "+", "2", "2", "*", "2", "*", "3", "*", "+" };
	root = insert_into_expression_tree(vec_38);
	result = et.evaluate(root);
	accumulated.push_back(result);

	vector<string> vec_39 = { "5", "2", "3", "*", "+", "2", "2", "*", "+", "7", "+", "7", "+", "5", "+", "7", "+", "3", "+", "5", "+", "2", "+" };
	root = insert_into_expression_tree(vec_39);
	result = et.evaluate(root);
	accumulated.push_back(result);

	vector<string> vec_40 = { "5", "5", "+", "7", "+", "2", "2", "*", "+", "7", "+", "7", "+", "3", "+", "5", "+", "2", "3", "*", "+", "2", "2", "*", "2", "*", "+" };
	root = insert_into_expression_tree(vec_40);
	result = et.evaluate(root);
	accumulated.push_back(result);

	vector<string> vec_41 = { "2", "3", "*", "7", "+", "2", "3", "*", "+", "5", "+", "3", "+", "5", "+", "5", "+", "3", "+", "5", "+", "11", "+" };
	root = insert_into_expression_tree(vec_41);
	result = et.evaluate(root);
	accumulated.push_back(result);

	vector<string> vec_42 = { "13", "2", "5", "*", "+", "2", "2", "*", "2", "*", "+", "2", "5", "*", "+", "2", "5", "*", "+", "2", "5", "*", "+", "2", "5", "*", "+", "3", "3", "*", "+", "11", "+", "2", "3", "*", "+" };
	root = insert_into_expression_tree(vec_42);
	result = et.evaluate(root);
	accumulated.push_back(result);

	vector<string> vec_43 = { "3", "3", "+", "3", "+", "2", "2", "*", "+", "7", "+", "7", "+", "5", "+", "5", "+", "3", "+", "2", "2", "*", "3", "*", "+" };
	root = insert_into_expression_tree(vec_43);
	result = et.evaluate(root);
	accumulated.push_back(result);

	vector<string> vec_44 = { "2", "3", "*", "2", "7", "*", "+", "5", "+", "13", "+", "7", "+", "13", "+", "2", "2", "*", "2", "*", "+", "5", "+", "11", "+", "2", "2", "*", "5", "*", "+" };
	root = insert_into_expression_tree(vec_44);
	result = et.evaluate(root);
	accumulated.push_back(result);

	vector<string> vec_45 = { "3", "3", "*", "2", "2", "*", "3", "*", "+", "2", "5", "*", "+", "3", "3", "*", "+", "2", "2", "*", "3", "*", "+", "5", "+", "3", "3", "*", "+", "2", "3", "*", "+", "11", "+", "3", "5", "*", "+" };
	root = insert_into_expression_tree(vec_45);
	result = et.evaluate(root);
	accumulated.push_back(result);

	vector<string> vec_46 = { "5", "2", "3", "*", "+", "2", "2", "*", "+", "2", "+", "3", "+", "2", "2", "*", "+", "2", "2", "*", "+", "2", "3", "*", "+", "3", "+", "11", "+" };
	root = insert_into_expression_tree(vec_46);
	result = et.evaluate(root);
	accumulated.push_back(result);

	vector<string> vec_47 = { "3", "3", "*", "3", "5", "*", "+", "2", "5", "*", "+", "2", "3", "*", "+", "2", "2", "*", "2", "*", "+", "7", "+", "2", "2", "*", "2", "*", "+", "2", "2", "*", "3", "*", "+", "2", "2", "*", "2", "*", "+", "2", "3", "*", "3", "*", "+" };
	root = insert_into_expression_tree(vec_47);
	result = et.evaluate(root);
	accumulated.push_back(result);

	vector<string> vec_48 = { "5", "3", "+", "5", "+", "5", "+", "2", "2", "*", "+", "2", "3", "*", "+", "5", "+", "7", "+", "2", "3", "*", "+", "5", "+" };
	root = insert_into_expression_tree(vec_48);
	result = et.evaluate(root);
	accumulated.push_back(result);

	vector<string> vec_49 = { "3", "3", "*", "7", "+", "2", "2", "*", "3", "*", "+", "2", "2", "*", "3", "*", "+", "2", "2", "*", "2", "*", "+", "3", "3", "*", "+", "2", "2", "*", "2", "*", "+", "13", "+", "11", "+", "3", "3", "*", "+" };
	root = insert_into_expression_tree(vec_49);
	result = et.evaluate(root);
	accumulated.push_back(result);

	vector<string> vec_50 = { "2", "2", "*", "3", "+", "2", "3", "*", "+", "5", "+", "2", "2", "*", "+", "3", "+", "5", "+", "3", "+", "7", "+", "2", "2", "*", "2", "*", "2", "*", "+" };
	root = insert_into_expression_tree(vec_50);
	result = et.evaluate(root);
	accumulated.push_back(result);

	vector<string> vec_51 = { "2", "2", "*", "3", "*", "2", "3", "*", "+", "13", "+", "13", "+", "2", "2", "*", "3", "*", "+", "3", "3", "*", "+", "3", "3", "*", "+", "2", "2", "*", "3", "*", "+", "13", "+" };
	root = insert_into_expression_tree(vec_51);
	result = et.evaluate(root);
	accumulated.push_back(result);

	vector<string> vec_52 = { "2", "7", "*", "2", "5", "*", "+", "2", "2", "*", "2", "*", "+", "2", "5", "*", "+", "13", "+", "2", "2", "*", "2", "*", "+", "13", "+", "3", "5", "*", "+", "2", "2", "*", "3", "*", "+" };
	root = insert_into_expression_tree(vec_52);
	result = et.evaluate(root);
	accumulated.push_back(result);

	vector<string> vec_53 = { "2", "3", "*", "2", "2", "*", "+", "2", "2", "*", "+", "5", "+", "3", "+", "5", "+", "7", "+", "2", "3", "*", "+", "5", "+", "11", "+" };
	root = insert_into_expression_tree(vec_53);
	result = et.evaluate(root);
	accumulated.push_back(result);

	vector<string> vec_54 = { "5", "5", "+", "5", "+", "7", "+", "5", "+", "7", "+", "5", "+", "7", "+", "3", "+", "3", "+" };
	root = insert_into_expression_tree(vec_54);
	result = et.evaluate(root);
	accumulated.push_back(result);

	vector<string> vec_55 = { "5", "2", "3", "*", "+", "3", "+", "2", "2", "*", "+", "5", "+", "2", "3", "*", "+", "2", "2", "*", "+", "2", "2", "*", "+", "2", "3", "*", "+", "2", "5", "*", "+" };
	root = insert_into_expression_tree(vec_55);
	result = et.evaluate(root);
	accumulated.push_back(result);

	vector<string> vec_56 = { "2", "2", "*", "2", "3", "*", "+", "2", "3", "*", "+", "7", "+", "2", "3", "*", "+", "5", "+", "5", "+", "5", "+", "2", "3", "*", "+", "5", "+" };
	root = insert_into_expression_tree(vec_56);
	result = et.evaluate(root);
	accumulated.push_back(result);

	vector<string> vec_57 = { "3", "2", "2", "*", "+", "2", "2", "*", "+", "5", "+", "2", "2", "*", "+", "5", "+", "2", "2", "*", "+", "2", "+", "5", "+", "13", "+" };
	root = insert_into_expression_tree(vec_57);
	result = et.evaluate(root);
	accumulated.push_back(result);

	vector<string> vec_58 = { "7", "7", "+", "7", "+", "5", "+", "2", "3", "*", "+", "2", "3", "*", "+", "2", "3", "*", "+", "5", "+", "5", "+" };
	root = insert_into_expression_tree(vec_58);
	result = et.evaluate(root);
	accumulated.push_back(result);

	vector<string> vec_59 = { "7", "3", "+", "3", "+", "5", "+", "2", "2", "*", "+", "5", "+", "2", "2", "*", "+", "2", "2", "*", "+", "2", "3", "*", "+", "2", "7", "*", "+" };
	root = insert_into_expression_tree(vec_59);
	result = et.evaluate(root);
	accumulated.push_back(result);

	vector<string> vec_60 = { "3", "5", "+", "2", "2", "*", "+", "2", "3", "*", "+", "3", "+", "7", "+", "7", "+", "2", "3", "*", "+", "2", "2", "*", "+", "2", "2", "*", "2", "*", "+" };
	root = insert_into_expression_tree(vec_60);
	result = et.evaluate(root);
	accumulated.push_back(result);

	vector<string> vec_61 = { "2", "2", "*", "2", "3", "*", "+", "3", "+", "2", "3", "*", "+", "3", "+", "3", "+", "3", "+", "3", "+", "5", "+", "17", "+" };
	root = insert_into_expression_tree(vec_61);
	result = et.evaluate(root);
	accumulated.push_back(result);

	vector<string> vec_62 = { "5", "3", "+", "2", "2", "*", "+", "3", "+", "2", "3", "*", "+", "7", "+", "2", "2", "*", "+", "5", "+", "7", "+", "2", "3", "*", "+" };
	root = insert_into_expression_tree(vec_62);
	result = et.evaluate(root);
	accumulated.push_back(result);

	vector<string> vec_63 = { "2", "2", "*", "2", "*", "2", "*", "2", "5", "*", "+", "11", "+", "11", "+", "2", "3", "*", "3", "*", "+", "13", "+", "2", "3", "*", "+", "17", "+", "2", "5", "*", "+", "13", "+" };
	root = insert_into_expression_tree(vec_63);
	result = et.evaluate(root);
	accumulated.push_back(result);



	string test = string(accumulated.begin(), accumulated.end());

	//cout << test << endl;

	int compare = test.compare(entered_flag);

	return compare;
}


int main() {
	// take user input, append into LL. walk the LL and compare flag to calculations using vec
	//string str = "ABC*+D/";
	//vector<string> vec = { "A", "B", "C", "*", "+", "D", "/" };
	//vector<string> vec = { "10", "11", "12", "*", "+", "4", "/" };
	//Leaf* root = insert_into_expression_tree(vec);
	////alternating_ll_append(str);
	////ll.print_list();
	//et.in_order(root);
	//int result = et.evaluate(root);

	//int result = check_flag(string("abcd"));
	//cout << "Expected: False, Actual: " << result << endl;
	//result = check_flag(string("SEE{5w1n61n6_7hr0u6h_7h3_7r335_51e72e7f398a4fb0e3b8cg8457167552}"));
	//cout << "Expected: True, Actual: " << result << endl;
	//result = check_flag(string("SEE{wrong_flag}"));
	//cout << "Expected: False, Actual: " << result << endl;

	cout << "Heard of a binary tree?" << endl;
	cout << "Heard of an expression tree?" << endl;
	cout << "Birds perch in trees too" << endl;
	cout << "What's the flag? >> ";
	string test;
	cin >> test;

	int flag_check = check_flag(test);

	if (flag_check == 0)
		cout << "Congrats!" << endl;
	else
		cout << "Try harder!" << endl;

	return 0;
}