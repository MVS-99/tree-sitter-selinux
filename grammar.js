module.exports = grammar({
    name: 'selinux',

    externals: $ => [
        $._IF,
        $._FC,
        $._TE,
    ],

    rules: {
        source_file: $ => seq(
            repeat($._statement),
        ),
        _statement: $ => choice(
            $._te_statements,
            $.common_statements
        ),

        _te_statements: $ => prec.dynamic(-1, seq(
            alias($._TE, $.te_marker),
            choice(
                $.policy_module_statement,
                $.type_declaration,
                $.attribute_declaration,
                $.access_vector_rules,
            ),
        )),
        
        // Add the module statement to a loadable module, and automatically
        // add a require statement with pre-defined information for all 
        // loadable modules such as the system_r role, kernel classes and 
        // permissions, and optionally MCS / MLS information 
        // (sensitivity and category statements)
        policy_module_statement: $ => seq(
            'policy_module',
            '(',
            field('policy_module_name', $.identifier),
            optional(
                seq(
                    ',',
                    field('policy_module_version', $.number)
                )
            ),
            ')',
            ';'
        ),
        
        // Declares the type identifier and any optional associated alias or
        // (previously declared) attribute identifiers. Type identifiers are 
        // a component of the Security Context.
        type_declaration: $ => seq(
            'type',
            field('type_id', $.type_identifier),
            optional(
                choice(
                    seq( // Alias defined but no attribute
                        choice(
                            field("alias_id", $.identifier),
                            seq(
                                '{',
                                field('alias_id_X', repeat(seq($.identifier, ' '))),
                                '}'
                            )
                        )
                    ),
                    seq( // Attribute defined but no alias
                        ',',
                        choice(
                            field("attribute_id", $.identifier),
                            seq(
                                '{',
                                field('attribute_id_X', repeat(seq($.identifier, ' '))),
                                '}'
                            )
                        )
                    ),
                    seq( // Both declared
                        choice(
                            field("alias_id", $.identifier),
                            seq(
                                '{',
                                field('alias_id_X', repeat(seq($.identifier, ' '))),
                                '}'
                            )
                        ),
                        ',',
                        choice(
                            field("attribute_id", $.identifier),
                            seq(
                                '{',
                                field('attribute_id_X', repeat(seq($.identifier, ' '))),
                                '}'
                            )
                        )
                    )
                )
            ),
            ';'
        ),
        
        // Declares an identifier that can be used to refer
        // to a group of type identifiers
        attribute_declaration: $ => seq(
            'attribute',
            field('attribute_id', $.identifier),
            ';'
        ),
        
        // @allow:
        // When scontext(s) have X obj_permission(s) for object_class(es) of tcontext(s)
        // the the event must be allowed
        // @auditallow:
        // When scontext(s) have X obj_permission(s) for object_class(es) of tcontext(s)
        // the event must be allowed and audited
        // @dontaudit:
        // When scontext(s) have X obj_permission(s) for object_class(es) of tcontext(s)
        // allow but dont audit
        // @neverallow:
        // Never allow even if an allow rule was previously stated for:
        // When scontext(s) have X obj_permission(s) for an object_class(es) of tcontext(s)
        access_vector_rules: $ => seq(
            choice(
                seq(
                    choice(
                        'allow',
                        'auditallow',
                        'dontaudit',
                    ),
                    choice(
                        // Source type, typeallias or attribute
                        field('source', $.identifier),
                        seq(                   
                            '{',
                            field('source_X', repeat(seq(optional('-'), $.identifier, ' '))),
                            $.identifier, // Last permission should not have a space
                            '}'
                        )
                    ),
                    choice(
                        // Target type, typeallias or attribute
                        field('target', $.identifier),
                        'self',
                        seq(                   
                            '{',
                            // - Represents the optional negative operator to explicitly
                            // exclude one from the list
                            field('target_X', repeat(seq(optional('-'), $.identifier, ' '))),
                            seq(optional('-'), $.identifier), 
                            '}'
                        )
                    ),
                    ':',
                    choice(
                        field('obj_class', $.identifier),
                        seq(                   
                            '{',
                            field('obj_class_X', repeat(seq($.identifier, ' '))),
                            $.identifier, // Last permission should not have a space
                            '}'
                        )
                    ),
                    choice(
                        field('obj_permission', $.identifier),
                        seq(
                            optional('~'),
                            '{',
                            field('obj_permission_X', repeat(seq($.identifier, ' '))),
                            $.identifier, // Last permission should not have a space
                            '}'
                        )
                    )
                ),
                seq(
                    'neverallow',
                    choice(
                        // Source type, typeallias or attribute
                        seq(
                            optional('~'), // Complement operator, all except the stated ones
                            field('source', $.identifier)
                        ),
                        '*', // Wildcard operator (all types)
                        seq(
                            optional('~'),
                            '{',
                            field('source_X', repeat(seq(optional('-'), $.identifier, ' '))),
                            $.identifier, // Last permission should not have a space
                            '}'
                        ),
                    ),
                    choice(
                        // Target type, typeallias or attribute
                        field('target', $.identifier),
                        'self',
                        seq(                   
                            '{',
                            // - Represents the optional negative operator to explicitly
                            // exclude one from the list
                            field('target_X', repeat(seq(optional('-'), $.identifier, ' '))),
                            seq(optional('-'), $.identifier), 
                            '}'
                        )
                    ),
                    ':',
                    choice(
                        field('obj_class', $.identifier),
                        seq(                   
                            '{',
                            field('obj_class_X', repeat(seq($.identifier, ' '))),
                            $.identifier, // Last permission should not have a space
                            '}'
                        )
                    ),
                    choice(
                        field('obj_permission', $.identifier),
                        '*',
                        seq(
                            optional('~'),
                            '{',
                            field('obj_permission_X', repeat(seq($.identifier, ' '))),
                            $.identifier, // Last permission should not have a space
                            '}'
                        )
                    )
                ),
                ';'
            )
        ),

        common_statements: $ => choice(
            $.comment,
        ),

        comment: $ => token(choice(
            seq('#', /.*/),
            seq(
                '/*',
                /[^*]*\*+([^/*][^*]*\*+)*/,
                '/'
            )
        )),

        identifier: $ => /[a-zA-Z_][a-zA-Z0-9_]*/,
        type_identifier: $ => /[a-zA-Z_][a-zA-Z0-9_]*_t/,
        number: $ => /\d+(\.\d+)?/
    }
});
