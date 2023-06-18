#pragma once

#include <iostream>

using namespace std;


class Node {
public:
	char data;
	Node* next;

	// Node methods
	Node() {
		data = 0;
		next = NULL;
	}

	Node(char data) {
		this->data = data;
		this->next = NULL;
	}

	friend class LinkedList;
};

class LinkedList {
	Node* head;
public:
	// Linked list methods
	LinkedList() { head = NULL; }
	void print_list();
	void delete_node(int position);
	void append_node_iterative(int data);
	void append_node_recursive(int data);
	void append_recursive_helper(Node* list, int data);
};

//void LinkedList::print_list() {
//	Node* temp = head;
//
//	if (head == NULL) {
//		return; // empty list
//	}
//
//	while (temp != NULL) {
//		cout << temp->data << endl;
//		temp = temp->next;
//	}
//}

//void LinkedList::delete_node(int node_position) {
//	Node* temp_1 = head;
//	Node* temp_2 = NULL;
//	int list_len = 0;
//
//	if (head == NULL) {
//		return; // list is empty
//	}
//
//	while (temp_1 != NULL) {
//		temp_1 = temp_1->next;
//		list_len++;
//	}
//
//	if (list_len < node_position) {
//		return; // invalid node position
//	}
//
//	temp_1 = head;
//
//	if (node_position == 1) { // deleting the head
//		head = head->next;
//		delete temp_1;
//		return;
//	}
//
//	while (node_position-- > 1) {
//		temp_2 = temp_1;
//		temp_1 = temp_1->next;
//	}
//
//	temp_2->next = temp_1->next;
//	delete temp_1;
//
//}

void LinkedList::append_node_iterative(int data) {
	Node* new_node = new Node(data);

	if (head == NULL) {
		head = new_node;
		return;
	}

	Node* temp = head;

	while (temp->next != NULL) {
		temp = temp->next;
	}

	temp->next = new_node;
}

void LinkedList::append_recursive_helper(Node* list, int data) {
	if (list->next != NULL)
		append_recursive_helper(list->next, data);
	else
		list->next = new Node(data);
}

void LinkedList::append_node_recursive(int data) {
	if (head == NULL)
		head = new Node(data);
	else
		append_recursive_helper(head, data);
}