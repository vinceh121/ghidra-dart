//@author vinceh121
//@category Dart
//@keybinding 
//@menupath 
//@toolbar 

import java.io.FileReader;

import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.mem.*;
import ghidra.program.model.lang.*;
import ghidra.program.model.pcode.*;
import ghidra.program.model.util.*;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;
import ghidra.program.model.reloc.*;
import ghidra.program.model.data.*;
import ghidra.program.model.block.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.scalar.*;
import ghidra.program.model.listing.*;
import ghidra.program.database.function.OverlappingFunctionException;
import ghidra.program.model.address.*;

public class ReadDartAnalysis extends GhidraScript {

	public void run() throws Exception {
		Gson gson = new Gson();
		JsonObject analysis = gson.fromJson(
				new FileReader("/home/vincent/Software/dartsdk/sdk/out/ProductX64C/owov134test.pp.json"),
				JsonObject.class);
		//// METHODS
		JsonArray classes = analysis.getAsJsonObject("class_table").getAsJsonArray("classes");
		for (JsonElement el : classes) {
			JsonObject cls = el.getAsJsonObject();
			if (cls.has("functions")) {
				JsonArray funcs = cls.getAsJsonArray("functions");
				for (JsonElement elF : funcs) {
					this.addFunction(cls.get("name").getAsString(), elF.getAsJsonObject());
				}
			}
		}

		//// CONSTANT POOL // Symbol dataLabel =
		this.getSymbols("_kDartIsolateSnapshotData", null).get(0);
		JsonArray objPool = analysis.getAsJsonArray("object_pool");
		for (JsonElement el : objPool) {
			JsonObject obj = el.getAsJsonObject();
			if ("kOneByteString".equals(obj.get("type").getAsString())) {
//				Address addr = dataLabel.getAddress().add(obj.get("offset").getAsLong());
				final int extra = 4;
				Address addr = getAddressFactory().getDefaultAddressSpace().getAddress(0x206EF7)
						.add(obj.get("offset").getAsLong()).subtract(extra);
				int length = obj.get("value").getAsString().length() + extra;
				if (length != 0) {
					try {
						this.createAsciiString(addr, length);
					} catch (CodeUnitInsertionException e) {
						println("Failed to create string " + obj.get("value"));
						e.printStackTrace();
					}
				}
			}
		}

	}

	private void addFunction(String clsName, JsonObject funcJs)
			throws AddressOutOfBoundsException, DuplicateNameException {
		Symbol label = this.getSymbols(funcJs.get("section").getAsString(), null).get(0);
		Address addr = label.getAddress().add(funcJs.get("offset").getAsLong());
		String funcName = clsName + "::" + funcJs.get("name").getAsString().replaceAll("[^a-zA-Z0-9]", "_");
		try {
			this.clearListing(addr, addr.add(funcJs.get("size").getAsLong()));
		} catch (CancelledException e) {
			println("Refused to clear lising");
		}
		Function existing = this.getFunctionAt(addr);
		if (existing != null) {
			try {
				existing.setName(existing.getName() + "--" + funcName, SourceType.USER_DEFINED);
			} catch (InvalidInputException e) {
				println("Couldn't append name of " + funcName + " to " + existing.getName());
			}
			return;
		}
		Function func = this.createFunction(addr, funcName);
		if (func == null) {
			println("Refused to create func " + funcName);
			return;
		}
		try {
			func.setBody(getAddressFactory().getAddressSet(addr, addr.add(funcJs.get("size").getAsLong())));
		} catch (OverlappingFunctionException e) {
			println("Overlap for func " + funcName);
		}
		func.setComment(funcJs.get("signature").getAsString());
	}
}
