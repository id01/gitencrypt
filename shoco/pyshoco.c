#include <stdlib.h>
#include <string.h>

#include <python3.6m/Python.h>

#include "shoco.h"

static PyObject* pyshoco_compress(PyObject* self, PyObject* args);
static PyObject* pyshoco_decompress(PyObject* self, PyObject* args);

static PyMethodDef pyshoco_methods[] = {
	{"compress", pyshoco_compress, METH_VARARGS, NULL},
	{"decompress", pyshoco_decompress, METH_VARARGS, NULL},
	{NULL, NULL}
};

static struct PyModuleDef moduledef = {
	PyModuleDef_HEAD_INIT,
	"pyshoco",
	NULL, -1,
	pyshoco_methods,
	NULL, NULL, NULL, NULL
};

static struct PyModuleDef shocomodule = {
	PyModuleDef_HEAD_INIT, "pyshoco", NULL, -1, pyshoco_methods
};

PyMODINIT_FUNC PyInit_pyshoco(void) {
	return PyModule_Create(&shocomodule);
}

static PyObject* pyshoco_compress(PyObject* self, PyObject* args) {
	const char* in; const size_t in_len;

	if (!PyArg_ParseTuple(args, "y#", &in, &in_len))
		return NULL;

	size_t buf_max_len = in_len*2+1;
	unsigned char* buf = malloc(buf_max_len);
	size_t buf_len = shoco_compress(in, in_len, buf, buf_max_len);
	return Py_BuildValue("y#", buf, buf_len);
}

static PyObject* pyshoco_decompress(PyObject* self, PyObject* args) {
	const char* in; const size_t in_len;

	if (!PyArg_ParseTuple(args, "y#", &in, &in_len))
		return NULL;

	size_t buf_max_len = in_len*12+1; // How large should this even be? I'll make it 12 times larger just in case
	unsigned char* buf = malloc(buf_max_len);
	size_t buf_len = shoco_decompress(in, in_len, buf, buf_max_len);
	return Py_BuildValue("y#", buf, buf_len);
}
