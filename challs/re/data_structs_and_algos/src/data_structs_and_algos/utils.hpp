#pragma once

#include <utility>
#include <type_traits>	
#include <vector>

using namespace std;

template<typename T, typename U>
auto forward_like(U&& u) -> typename enable_if<is_lvalue_reference<T>::value, U&>::type {
	return u;
}

template <typename T, typename U>
auto forward_like(U&& u) -> typename enable_if<!is_lvalue_reference<T>::value, typename remove_reference<U>::type&&>::type {
	return move(u);
}

template <typename Container, typename F>
void enumerate(Container&& c, F&& f) {
	size_t i = 0;
	for (auto&& x : forward<Container>(c)) {
		f(i++, forward_like<Container>(x));
	}
}